extern crate std;
use super::*;
use soroban_sdk::{
    Env, IntoVal, Map, Symbol, TryFromVal, Val, contract, contractimpl, testutils::Address as _,
    vec, xdr::ToXdr,
};

/// Contract scope for the temporary-storage write buffer.
#[contract]
struct Scope;
#[contractimpl]
impl Scope {}

/// Every canonical rule in Grant field order.
const ALL: [AllowitRule; 8] = [
    AllowitRule::transaction_cap,
    AllowitRule::spent_cap,
    AllowitRule::day_spent_cap,
    AllowitRule::day_total_cap,
    AllowitRule::call_cap,
    AllowitRule::recipients,
    AllowitRule::tokens,
    AllowitRule::expiry,
];

/// Fails to compile when a variant is added without extending `ALL`.
fn position(rule: AllowitRule) -> usize {
    match rule {
        AllowitRule::transaction_cap => 0,
        AllowitRule::spent_cap => 1,
        AllowitRule::day_spent_cap => 2,
        AllowitRule::day_total_cap => 3,
        AllowitRule::call_cap => 4,
        AllowitRule::recipients => 5,
        AllowitRule::tokens => 6,
        AllowitRule::expiry => 7,
    }
}

/// The state map of standard values `s`.
fn map(env: &Env, s: &AllowitStandardState) -> AllowitStateMap {
    let mut state = Map::new(env);
    s.write(env, &mut state).unwrap();
    state
}

/// Edit the standard values of `ctx.state`.
fn edit(ctx: &mut AllowitContext, change: impl FnOnce(&mut AllowitStandardState)) {
    let mut s = AllowitStandardState::read(&ctx.env, &ctx.state).unwrap();
    change(&mut s);
    s.write(&ctx.env, &mut ctx.state).unwrap();
}

/// Current state before a 40-unit priced transfer: after it, spent and day_spent are 45 and
/// day_total is 43.
fn fixture(env: &Env) -> AllowitContext {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    AllowitContext {
        env: env.clone(),
        grant: AllowitGrant {
            transaction_cap: Some(100),
            spent_cap: Some(1000),
            day_spent_cap: Some(500),
            day_total_cap: Some(600),
            call_cap: Some(3),
            recipients: Some(vec![env, recipient.clone()]),
            tokens: Some(vec![env, asset.clone()]),
            expiry: Some(999_999),
        },
        state: map(
            env,
            &AllowitStandardState {
                calls: 1,
                spent: 5,
                day: 1,
                day_spent: 5,
                day_total: 3,
                ..Default::default()
            },
        ),
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset,
            recipient,
            amount: 40,
            now: DAY + 100,
            expires_at: DAY + 500,
            spent_units: 40,
            gas_units: 0,
            unpriced: false,
        },
    }
}

#[test]
fn rules_return_exact_passing_constraints_after_this_operation() {
    let env = Env::default();
    let ctx = fixture(&env);
    let g = &ctx.grant;
    assert_eq!(transaction_cap(&ctx, &g.transaction_cap), Ok(60));
    assert_eq!(spent_cap(&ctx, &g.spent_cap), Ok(955));
    assert_eq!(day_spent_cap(&ctx, &g.day_spent_cap), Ok(455));
    assert_eq!(day_total_cap(&ctx, &g.day_total_cap), Ok(557));
    assert_eq!(call_cap(&ctx, &g.call_cap), Ok(1));
    assert_eq!(
        recipients(&ctx, &g.recipients),
        Ok(ctx.request.recipient.clone())
    );
    assert_eq!(tokens(&ctx, &g.tokens), Ok(ctx.request.asset.clone()));
    assert_eq!(expiry(&ctx, &g.expiry), Ok(999_999 - DAY - 100));
    for rule in ALL {
        assert_eq!(preflight(&ctx, rule), Ok(()));
    }
    assert_eq!(ctx.grant.validate(), Ok(()));
    // Gas counts toward the daily gross total only.
    let mut gas = ctx.clone();
    gas.request.gas_units = 7;
    gas.request.spent_units = 47;
    assert_eq!(spent_cap(&gas, &g.spent_cap), Ok(948));
    assert_eq!(day_total_cap(&gas, &g.day_total_cap), Ok(550));
    // An empty state map is a fresh wallet: every standard value is zero.
    let mut fresh = ctx.clone();
    fresh.state = Map::new(&env);
    assert_eq!(spent_cap(&fresh, &g.spent_cap), Ok(960));
    assert_eq!(day_total_cap(&fresh, &g.day_total_cap), Ok(560));
    assert_eq!(call_cap(&fresh, &g.call_cap), Ok(2));
}

#[test]
fn unset_grant_fields_deny_in_rules_and_skip_only_in_preflight() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    ctx.grant = AllowitGrant::default();
    assert_eq!(
        transaction_cap(&ctx, &None),
        Err(AllowitError::MissingGrant)
    );
    assert_eq!(spent_cap(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(day_spent_cap(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(day_total_cap(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(call_cap(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(recipients(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(tokens(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(expiry(&ctx, &None), Err(AllowitError::MissingGrant));
    // MissingGrant precedes every request and state check.
    ctx.request.amount = 0;
    ctx.request.now = ctx.request.expires_at + 1;
    edit(&mut ctx, |s| {
        s.day = u64::MAX;
        s.unpriced = true;
        s.calls = u64::MAX;
    });
    assert_eq!(spent_cap(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(call_cap(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(expiry(&ctx, &None), Err(AllowitError::MissingGrant));
    for rule in ALL {
        assert_eq!(preflight(&ctx, rule), Ok(()));
    }
    // A set field is checked by preflight exactly as by the rule.
    ctx.grant.spent_cap = Some(1000);
    assert_eq!(
        preflight(&ctx, AllowitRule::spent_cap),
        Err(AllowitError::Unpriced)
    );
    ctx.grant.expiry = Some(u64::MAX);
    assert_eq!(
        preflight(&ctx, AllowitRule::expiry),
        Err(AllowitError::Expired)
    );
    ctx.grant.call_cap = Some(u64::MAX);
    assert_eq!(
        preflight(&ctx, AllowitRule::call_cap),
        Err(AllowitError::Overflow)
    );
}

#[test]
fn boundary_equality_passes_with_zero_headroom_and_one_more_denies() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    assert_eq!(transaction_cap(&ctx, &Some(40)), Ok(0));
    assert_eq!(spent_cap(&ctx, &Some(45)), Ok(0));
    assert_eq!(day_spent_cap(&ctx, &Some(45)), Ok(0));
    assert_eq!(day_total_cap(&ctx, &Some(43)), Ok(0));
    assert_eq!(call_cap(&ctx, &Some(2)), Ok(0));
    assert_eq!(
        expiry(&ctx, &Some(ctx.request.expires_at)),
        Ok(ctx.request.expires_at - ctx.request.now)
    );
    assert_eq!(
        expiry(&ctx, &Some(ctx.request.now + 1)),
        Err(AllowitError::Expired)
    );
    assert_eq!(
        transaction_cap(&ctx, &Some(39)),
        Err(AllowitError::TransactionCapExceeded)
    );
    assert_eq!(
        spent_cap(&ctx, &Some(44)),
        Err(AllowitError::SpentCapExceeded)
    );
    assert_eq!(
        day_spent_cap(&ctx, &Some(44)),
        Err(AllowitError::DaySpentCapExceeded)
    );
    assert_eq!(
        day_total_cap(&ctx, &Some(42)),
        Err(AllowitError::DayTotalCapExceeded)
    );
    assert_eq!(call_cap(&ctx, &Some(1)), Err(AllowitError::CallCapExceeded));
    // This operation counts as a call, so a zero cap always denies.
    ctx.state = Map::new(&env);
    assert_eq!(call_cap(&ctx, &Some(0)), Err(AllowitError::CallCapExceeded));
    assert_eq!(call_cap(&ctx, &Some(1)), Ok(0));
}

#[test]
fn accounting_caps_check_only_the_facts_they_read() {
    let env = Env::default();
    let base = fixture(&env);
    type Cap = fn(&AllowitContext, &Option<i128>) -> Result<i128>;
    let caps: [Cap; 3] = [spent_cap, day_spent_cap, day_total_cap];
    let passing = [955, 955, 957];
    let edits: [fn(&mut AllowitContext); 11] = [
        |c| c.request.amount = 0,
        |c| edit(c, |s| s.day -= 1),
        |c| edit(c, |s| s.day += 1),
        |c| edit(c, |s| s.spent = -1),
        |c| edit(c, |s| s.day_spent = -1),
        |c| edit(c, |s| s.day_total = -1),
        |c| edit(c, |s| s.unpriced = true),
        |c| edit(c, |s| s.day_unpriced = true),
        |c| c.request.unpriced = true,
        |c| c.request.spent_units = -1,
        |c| c.request.gas_units = -1,
    ];
    use AllowitError::{InvalidParameter as P, InvalidState as S, Unpriced as U};
    // Expected result per edit, for spent_cap, day_spent_cap and day_total_cap. `None` passes,
    // `Some(Ok(v))` passes with `v`.
    let rolled = Some(Ok(1000 - 40));
    let expected: [[Option<core::result::Result<i128, AllowitError>>; 3]; 11] = [
        [None, None, Some(Ok(997))],
        // Daily values of an earlier day roll over to zero; a later day is invalid.
        [None, rolled, rolled],
        [None, Some(Err(S)), Some(Err(S))],
        [Some(Err(S)), None, None],
        [None, Some(Err(S)), None],
        [None, None, Some(Err(S))],
        [Some(Err(U)), None, None],
        [None, Some(Err(U)), Some(Err(U))],
        [Some(Err(U)), Some(Err(U)), Some(Err(U))],
        [Some(Err(P)), Some(Err(P)), None],
        [None, None, Some(Err(P))],
    ];
    for (i, (change, expected)) in edits.iter().zip(expected).enumerate() {
        let mut ctx = base.clone();
        change(&mut ctx);
        for (j, cap) in caps.iter().enumerate() {
            let want = expected[j].unwrap_or(Ok(passing[j]));
            assert_eq!(cap(&ctx, &Some(1000)), want, "edit {i} cap {j}");
        }
    }
    for cap in caps {
        assert_eq!(cap(&base, &Some(-1)), Err(AllowitError::InvalidParameter));
    }
    let mut ctx = base.clone();
    assert_eq!(
        transaction_cap(&ctx, &Some(-1)),
        Err(AllowitError::InvalidParameter)
    );
    ctx.request.amount = 0;
    assert_eq!(
        transaction_cap(&ctx, &Some(100)),
        Err(AllowitError::InvalidParameter)
    );
    // A standard key of another type is invalid state for every rule that reads state.
    let mut ctx = base.clone();
    ctx.state
        .set(Symbol::new(&env, "calls"), 1i128.into_val(&env));
    assert_eq!(call_cap(&ctx, &Some(3)), Err(AllowitError::InvalidState));
    assert_eq!(
        spent_cap(&ctx, &Some(1000)),
        Err(AllowitError::InvalidState)
    );
    assert_eq!(transaction_cap(&ctx, &Some(100)), Ok(60));
    // Sums that leave the integer range overflow.
    let mut ctx = base.clone();
    edit(&mut ctx, |s| s.spent = i128::MAX);
    assert_eq!(spent_cap(&ctx, &Some(1)), Err(AllowitError::Overflow));
}

#[test]
fn preflight_enforces_every_set_field_with_its_rule_error() {
    let env = Env::default();
    let other = Address::generate(&env);
    for rule in ALL {
        let mut ctx = fixture(&env);
        let now = ctx.request.now;
        let g = &mut ctx.grant;
        let expected = match rule {
            AllowitRule::transaction_cap => {
                g.transaction_cap = Some(39);
                AllowitError::TransactionCapExceeded
            }
            AllowitRule::spent_cap => {
                g.spent_cap = Some(44);
                AllowitError::SpentCapExceeded
            }
            AllowitRule::day_spent_cap => {
                g.day_spent_cap = Some(44);
                AllowitError::DaySpentCapExceeded
            }
            AllowitRule::day_total_cap => {
                g.day_total_cap = Some(42);
                AllowitError::DayTotalCapExceeded
            }
            AllowitRule::call_cap => {
                g.call_cap = Some(1);
                AllowitError::CallCapExceeded
            }
            AllowitRule::recipients => {
                g.recipients = Some(vec![&env, other.clone()]);
                AllowitError::RecipientNotAllowed
            }
            AllowitRule::tokens => {
                g.tokens = Some(vec![&env, other.clone()]);
                AllowitError::TokenNotAllowed
            }
            AllowitRule::expiry => {
                g.expiry = Some(now);
                AllowitError::Expired
            }
        };
        assert_eq!(preflight(&ctx, rule), Err(expected));
        // Only the edited rule denies.
        for other in ALL.into_iter().filter(|r| *r != rule) {
            assert_eq!(preflight(&ctx, other), Ok(()));
        }
    }
}

#[test]
fn allowlists_match_exact_addresses_and_empty_lists_deny() {
    let env = Env::default();
    let ctx = fixture(&env);
    let other = Address::generate(&env);
    assert_eq!(
        recipients(&ctx, &Some(vec![&env])),
        Err(AllowitError::RecipientNotAllowed)
    );
    assert_eq!(
        recipients(&ctx, &Some(vec![&env, other.clone()])),
        Err(AllowitError::RecipientNotAllowed)
    );
    assert_eq!(
        recipients(
            &ctx,
            &Some(vec![&env, other.clone(), ctx.request.recipient.clone()])
        ),
        Ok(ctx.request.recipient.clone())
    );
    assert_eq!(
        tokens(&ctx, &Some(vec![&env])),
        Err(AllowitError::TokenNotAllowed)
    );
    assert_eq!(
        tokens(&ctx, &Some(vec![&env, ctx.request.recipient.clone()])),
        Err(AllowitError::TokenNotAllowed)
    );
}

#[test]
fn expiry_bounds_grant_and_request() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    let now = ctx.request.now;
    assert_eq!(expiry(&ctx, &Some(now)), Err(AllowitError::Expired));
    // A request cannot outlive the grant.
    assert_eq!(
        expiry(&ctx, &Some(ctx.request.expires_at - 1)),
        Err(AllowitError::Expired)
    );
    ctx.request.expires_at = now;
    assert_eq!(expiry(&ctx, &Some(now + 10)), Err(AllowitError::Expired));
}

#[test]
fn rules_encode_as_their_canonical_names_and_other_names_do_not_decode() {
    let env = Env::default();
    let symbol = |name: &str| -> Val { vec![&env, Symbol::new(&env, name)].into_val(&env) };
    for (i, rule) in ALL.into_iter().enumerate() {
        assert_eq!(position(rule), i);
        let name = std::format!("{rule:?}");
        assert_eq!(rule.to_xdr(&env), symbol(&name).to_xdr(&env));
        assert_eq!(
            AllowitRule::try_from_val(&env, &symbol(&name)).ok(),
            Some(rule)
        );
    }
    for name in [
        "set_cap_per_day",
        "cap_per_transaction",
        "require_recipient",
        "require_asset",
        "allow_actions",
        "state_remove",
        "fail",
        "daily_cap",
        "total_cap",
        "recipient",
        "token",
        "per_transfer",
        "max_calls",
        "daily_limit",
        "Spent_cap",
        "",
    ] {
        // The host rejects an unknown variant symbol; inside a contract the invocation aborts.
        let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AllowitRule::try_from_val(&env, &symbol(name)).ok()
        }));
        assert!(matches!(decoded, Ok(None) | Err(_)));
    }
}

#[test]
fn grant_validation_rejects_only_negative_caps() {
    let env = Env::default();
    let grant = fixture(&env).grant;
    assert_eq!(AllowitGrant::default().validate(), Ok(()));
    for field in 0..4 {
        let mut bad = grant.clone();
        *[
            &mut bad.transaction_cap,
            &mut bad.spent_cap,
            &mut bad.day_spent_cap,
            &mut bad.day_total_cap,
        ][field] = Some(-1);
        assert_eq!(bad.validate(), Err(AllowitError::InvalidParameter));
    }
    let mut zero = grant;
    zero.call_cap = Some(0);
    zero.spent_cap = Some(0);
    zero.recipients = Some(vec![&env]);
    assert_eq!(zero.validate(), Ok(()));
}

/// Catches a spending cap error, reads it and continues; propagates the daily cap error.
fn catching(ctx: &AllowitContext) -> Result {
    if let Err(error) = spent_cap(ctx, &ctx.grant.spent_cap) {
        set_state(ctx, "caught", error as u64)?;
    }
    day_spent_cap(ctx, &ctx.grant.day_spent_cap)?;
    Ok(())
}

#[test]
fn a_caught_rule_error_lets_the_policy_continue_and_only_a_returned_error_denies() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let mut ctx = fixture(&env);
    env.as_contract(&id, || {
        ctx.grant.spent_cap = Some(1);
        assert_eq!(catching(&ctx), Ok(()));
        // The policy saw the error and recorded it; post-flight applies the write.
        let next = post_flight(&ctx).unwrap();
        let code = AllowitError::SpentCapExceeded as u64;
        assert_eq!(read::<u64>(&env, &next, "caught"), Ok(Some(code)));
        ctx.grant.day_spent_cap = Some(1);
        assert_eq!(catching(&ctx), Err(AllowitError::DaySpentCapExceeded));
    });
}

#[test]
fn post_flight_adds_this_operation_to_current_state_then_applies_policy_writes() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let ctx = fixture(&env);
    env.as_contract(&id, || {
        let next = post_flight(&ctx).unwrap();
        let s = AllowitStandardState::read(&env, &next).unwrap();
        let expected = AllowitStandardState {
            calls: 2,
            spent: 45,
            day: 1,
            day_spent: 45,
            day_total: 43,
            ..Default::default()
        };
        assert_eq!(s, expected);
        // A rule that passes on the current state holds on the post-flight state.
        let g = &ctx.grant;
        let left = spent_cap(&ctx, &g.spent_cap).unwrap();
        assert_eq!(g.spent_cap.unwrap() - s.spent, left);
        let left = call_cap(&ctx, &g.call_cap).unwrap();
        assert_eq!(g.call_cap.unwrap() - s.calls, left);

        // The next day rolls the daily values over; unpriced marks both liabilities.
        let mut later = ctx.clone();
        later.request.now += DAY;
        later.request.unpriced = true;
        later.request.spent_units = 0;
        let s = AllowitStandardState::read(&env, &post_flight(&later).unwrap()).unwrap();
        let expected = AllowitStandardState {
            calls: 2,
            spent: 5,
            unpriced: true,
            day: 2,
            day_spent: 0,
            day_total: 40,
            day_unpriced: true,
        };
        assert_eq!(s, expected);

        // Policy writes apply after the standard update and may replace a standard key.
        set_state(&ctx, "mine", 7i128).unwrap();
        set_state(&ctx, "calls", 99u64).unwrap();
        set_state(&ctx, "mine", 8i128).unwrap();
        // Reads see the state before this operation.
        assert_eq!(get_state::<i128>(&ctx, "mine"), Ok(None));
        assert_eq!(get_state::<u64>(&ctx, "calls"), Ok(Some(1)));
        let next = post_flight(&ctx).unwrap();
        assert_eq!(read::<i128>(&env, &next, "mine"), Ok(Some(8)));
        assert_eq!(read::<u64>(&env, &next, "calls"), Ok(Some(99)));
        // The buffer is consumed: neither a temporary entry nor a later write remains.
        use soroban_sdk::testutils::storage::Temporary as _;
        assert!(env.storage().temporary().all().is_empty());
        let next = post_flight(&ctx).unwrap();
        assert_eq!(read::<i128>(&env, &next, "mine"), Ok(None));
        assert_eq!(read::<u64>(&env, &next, "calls"), Ok(Some(2)));
    });
}

#[test]
fn post_flight_and_state_access_reject_invalid_keys_values_days_and_overflow() {
    let env = Env::default();
    let id = env.register(Scope, ());
    let ctx = fixture(&env);
    env.as_contract(&id, || {
        for key in ["", "has space", "dash-key", "x".repeat(33).as_str()] {
            assert_eq!(
                set_state(&ctx, key, 1u64),
                Err(AllowitError::InvalidParameter)
            );
            assert_eq!(
                get_state::<u64>(&ctx, key),
                Err(AllowitError::InvalidParameter)
            );
        }
        assert_eq!(set_state(&ctx, &"x".repeat(32), 1u64), Ok(()));
        assert!(post_flight(&ctx).is_ok());
        assert_eq!(
            get_state::<bool>(&ctx, "calls"),
            Err(AllowitError::InvalidState)
        );
        type Edit = fn(&mut AllowitContext);
        let cases: [(Edit, AllowitError); 6] = [
            (|c| edit(c, |s| s.day += 1), AllowitError::InvalidState),
            (|c| edit(c, |s| s.spent = -1), AllowitError::InvalidState),
            (
                |c| edit(c, |s| s.day_total = -1),
                AllowitError::InvalidState,
            ),
            (|c| edit(c, |s| s.calls = u64::MAX), AllowitError::Overflow),
            (|c| edit(c, |s| s.spent = i128::MAX), AllowitError::Overflow),
            (|c| c.request.gas_units = -1, AllowitError::InvalidParameter),
        ];
        for (change, error) in cases {
            let mut bad = ctx.clone();
            change(&mut bad);
            set_state(&bad, "mine", 1u64).unwrap();
            assert_eq!(post_flight(&bad), Err(error));
            // A failed post-flight still consumed the buffer.
            assert_eq!(
                read::<u64>(&env, &post_flight(&ctx).unwrap(), "mine"),
                Ok(None)
            );
        }
    });
}
