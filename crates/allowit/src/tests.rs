extern crate std;
use super::*;
use soroban_sdk::{
    Env, IntoVal, Symbol, TryFromVal, Val, testutils::Address as _, vec, xdr::ToXdr,
};

/// Every canonical rule in AllowitGrant field order.
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

fn fixture(env: &Env) -> AllowitContext {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    AllowitContext {
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
        state: AllowitAccountingHistory {
            calls: 1,
            spent: 45,
            day: 1,
            day_spent: 45,
            day_total: 43,
            ..Default::default()
        },
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset,
            recipient,
            amount: 40,
            now: DAY + 100,
            expires_at: DAY + 500,
        },
    }
}

#[test]
fn rules_return_exact_passing_constraints() {
    let env = Env::default();
    let ctx = fixture(&env);
    let g = &ctx.grant;
    assert_eq!(transaction_cap(&ctx, &g.transaction_cap), Ok(60));
    assert_eq!(spent_cap(&ctx, &g.spent_cap), Ok(955));
    assert_eq!(day_spent_cap(&ctx, &g.day_spent_cap), Ok(455));
    assert_eq!(day_total_cap(&ctx, &g.day_total_cap), Ok(557));
    assert_eq!(call_cap(&ctx, &g.call_cap), Ok(2));
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
}

#[test]
fn unset_grant_fields_deny_in_rules_and_preflight() {
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
    ctx.state.day = 0;
    ctx.state.unpriced = true;
    ctx.state.calls = u64::MAX;
    assert_eq!(spent_cap(&ctx, &None), Err(AllowitError::MissingGrant));
    assert_eq!(expiry(&ctx, &None), Err(AllowitError::MissingGrant));
    // Preflight runs the same unguarded call, so an unset prefix field denies onchain too.
    for rule in ALL {
        assert!(!ctx.grant.is_set(rule));
        assert_eq!(preflight(&ctx, rule), Err(AllowitError::MissingGrant));
    }
    // A set field is checked by preflight exactly as by the rule.
    ctx.grant.spent_cap = Some(1000);
    assert!(ctx.grant.is_set(AllowitRule::spent_cap));
    assert_eq!(
        preflight(&ctx, AllowitRule::spent_cap),
        Err(AllowitError::Unpriced)
    );
    ctx.grant.expiry = Some(u64::MAX);
    assert_eq!(
        preflight(&ctx, AllowitRule::expiry),
        Err(AllowitError::Expired)
    );
}

#[test]
fn boundary_equality_passes_with_zero_headroom_and_one_more_denies() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    let s = ctx.state.clone();
    assert_eq!(transaction_cap(&ctx, &Some(40)), Ok(0));
    assert_eq!(spent_cap(&ctx, &Some(s.spent)), Ok(0));
    assert_eq!(day_spent_cap(&ctx, &Some(s.day_spent)), Ok(0));
    assert_eq!(day_total_cap(&ctx, &Some(s.day_total)), Ok(0));
    assert_eq!(call_cap(&ctx, &Some(1)), Ok(0));
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
        spent_cap(&ctx, &Some(s.spent - 1)),
        Err(AllowitError::SpentCapExceeded)
    );
    assert_eq!(
        day_spent_cap(&ctx, &Some(s.day_spent - 1)),
        Err(AllowitError::DaySpentCapExceeded)
    );
    assert_eq!(
        day_total_cap(&ctx, &Some(s.day_total - 1)),
        Err(AllowitError::DayTotalCapExceeded)
    );
    ctx.state.calls = 2;
    assert_eq!(call_cap(&ctx, &Some(1)), Err(AllowitError::CallCapExceeded));
    // The protected count already includes this operation.
    ctx.state.calls = 0;
    assert_eq!(call_cap(&ctx, &Some(0)), Err(AllowitError::CallCapExceeded));
}

#[test]
fn accounting_caps_check_only_the_facts_they_read() {
    let env = Env::default();
    let base = fixture(&env);
    type Cap = fn(&AllowitContext, &Option<i128>) -> Result<i128>;
    let caps: [Cap; 3] = [spent_cap, day_spent_cap, day_total_cap];
    let passing = [955, 955, 957];
    let edits: [fn(&mut AllowitContext); 7] = [
        |c| c.request.amount = 0,
        |c| c.state.day += 1,
        |c| c.state.spent = -1,
        |c| c.state.day_spent = -1,
        |c| c.state.day_total = -1,
        |c| c.state.unpriced = true,
        |c| c.state.day_unpriced = true,
    ];
    use AllowitError::{InvalidState as S, Unpriced as U};
    // Expected result per edit, for spent_cap, day_spent_cap and day_total_cap. `None` passes.
    let expected: [[Option<AllowitError>; 3]; 7] = [
        [None, None, None],
        [None, Some(S), Some(S)],
        [Some(S), None, None],
        [None, Some(S), None],
        [None, None, Some(S)],
        [Some(U), None, None],
        [None, Some(U), Some(U)],
    ];
    for (edit, expected) in edits.iter().zip(expected) {
        let mut ctx = base.clone();
        edit(&mut ctx);
        for i in 0..3 {
            let result = caps[i](&ctx, &Some(1000));
            assert_eq!(result, expected[i].map_or(Ok(passing[i]), Err));
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
                g.call_cap = Some(0);
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
