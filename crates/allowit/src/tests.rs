extern crate std;
use super::*;
use soroban_sdk::{
    Env, IntoVal, String, Symbol, TryFromVal, Val, testutils::Address as _, vec, xdr::ToXdr,
};

/// Every canonical rule in Grant field order.
const ALL: [Rule; 8] = [
    Rule::transaction_cap,
    Rule::spent_cap,
    Rule::day_spent_cap,
    Rule::day_total_cap,
    Rule::call_cap,
    Rule::recipients,
    Rule::tokens,
    Rule::expiry,
];

/// Fails to compile when a variant is added without extending `ALL`.
fn position(rule: Rule) -> usize {
    match rule {
        Rule::transaction_cap => 0,
        Rule::spent_cap => 1,
        Rule::day_spent_cap => 2,
        Rule::day_total_cap => 3,
        Rule::call_cap => 4,
        Rule::recipients => 5,
        Rule::tokens => 6,
        Rule::expiry => 7,
    }
}

fn fixture(env: &Env) -> AllowitEnv {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    AllowitEnv {
        grant: Grant {
            transaction_cap: Some(100),
            spent_cap: Some(1000),
            day_spent_cap: Some(500),
            day_total_cap: Some(600),
            call_cap: Some(3),
            recipients: Some(vec![env, recipient.clone()]),
            tokens: Some(vec![env, asset.clone()]),
            expiry: Some(999_999),
        },
        state: AccountingHistory {
            calls: 1,
            spent: 45,
            day: 1,
            day_spent: 45,
            day_total: 43,
            ..Default::default()
        },
        request: Request {
            operation: String::from_str(env, "stellar::sep41_transfer"),
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
    assert_eq!(expiry(&ctx, &g.expiry), Ok(400));
    for rule in ALL {
        assert_eq!(preflight(&ctx, rule), Ok(()));
    }
    assert_eq!(ctx.grant.validate(), Ok(()));
}

#[test]
fn unset_grant_fields_deny_in_rules_and_skip_only_in_preflight() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    ctx.grant = Grant::default();
    assert_eq!(transaction_cap(&ctx, &None), Err(Error::MissingGrant));
    assert_eq!(spent_cap(&ctx, &None), Err(Error::MissingGrant));
    assert_eq!(day_spent_cap(&ctx, &None), Err(Error::MissingGrant));
    assert_eq!(day_total_cap(&ctx, &None), Err(Error::MissingGrant));
    assert_eq!(call_cap(&ctx, &None), Err(Error::MissingGrant));
    assert_eq!(recipients(&ctx, &None), Err(Error::MissingGrant));
    assert_eq!(tokens(&ctx, &None), Err(Error::MissingGrant));
    assert_eq!(expiry(&ctx, &None), Err(Error::MissingGrant));
    // MissingGrant precedes every request and state check.
    ctx.request.amount = 0;
    ctx.request.now = ctx.request.expires_at + 1;
    ctx.state.day = 0;
    ctx.state.unpriced = true;
    ctx.state.calls = u64::MAX;
    assert_eq!(spent_cap(&ctx, &None), Err(Error::MissingGrant));
    assert_eq!(expiry(&ctx, &None), Err(Error::MissingGrant));
    for rule in ALL {
        assert_eq!(preflight(&ctx, rule), Ok(()));
    }
    // A set field is checked by preflight exactly as by the rule.
    ctx.grant.spent_cap = Some(1000);
    assert_eq!(
        preflight(&ctx, Rule::spent_cap),
        Err(Error::InvalidParameter)
    );
    ctx.grant.expiry = Some(u64::MAX);
    assert_eq!(preflight(&ctx, Rule::expiry), Err(Error::Expired));
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
        transaction_cap(&ctx, &Some(39)),
        Err(Error::TransactionCapExceeded)
    );
    assert_eq!(
        spent_cap(&ctx, &Some(s.spent - 1)),
        Err(Error::SpentCapExceeded)
    );
    assert_eq!(
        day_spent_cap(&ctx, &Some(s.day_spent - 1)),
        Err(Error::DaySpentCapExceeded)
    );
    assert_eq!(
        day_total_cap(&ctx, &Some(s.day_total - 1)),
        Err(Error::DayTotalCapExceeded)
    );
    ctx.state.calls = 2;
    assert_eq!(call_cap(&ctx, &Some(1)), Err(Error::CallCapExceeded));
    // The protected count already includes this operation.
    ctx.state.calls = 0;
    assert_eq!(call_cap(&ctx, &Some(0)), Err(Error::CallCapExceeded));
}

#[test]
fn accounting_caps_reject_invalid_inputs_unpriced_and_other_days() {
    let env = Env::default();
    let base = fixture(&env);
    type Cap = fn(&AllowitEnv, &Option<i128>) -> Result<i128>;
    let caps: [(Cap, bool); 3] = [
        (spent_cap, false),
        (day_spent_cap, true),
        (day_total_cap, true),
    ];
    for (f, daily) in caps {
        let mut ctx = base.clone();
        assert_eq!(f(&ctx, &Some(-1)), Err(Error::InvalidParameter));
        ctx.request.amount = 0;
        assert_eq!(f(&ctx, &Some(1000)), Err(Error::InvalidParameter));
        let mut ctx = base.clone();
        ctx.state.day += 1;
        assert_eq!(f(&ctx, &Some(1000)), Err(Error::InvalidState));
        let mut ctx = base.clone();
        ctx.state.day_total = -1;
        assert_eq!(f(&ctx, &Some(1000)), Err(Error::InvalidState));
        let mut ctx = base.clone();
        ctx.state.day_unpriced = true;
        assert_eq!(
            f(&ctx, &Some(1000)),
            if daily { Err(Error::Unpriced) } else { Ok(955) }
        );
        let mut ctx = base.clone();
        ctx.state.unpriced = true;
        assert_eq!(
            f(&ctx, &Some(1000)),
            if daily {
                Ok(f(&base, &Some(1000)).unwrap())
            } else {
                Err(Error::Unpriced)
            }
        );
    }
    let mut ctx = base.clone();
    assert_eq!(
        transaction_cap(&ctx, &Some(-1)),
        Err(Error::InvalidParameter)
    );
    ctx.request.amount = 0;
    assert_eq!(
        transaction_cap(&ctx, &Some(100)),
        Err(Error::InvalidParameter)
    );
}

#[test]
fn allowlists_match_exact_addresses_and_empty_lists_deny() {
    let env = Env::default();
    let ctx = fixture(&env);
    let other = Address::generate(&env);
    assert_eq!(
        recipients(&ctx, &Some(vec![&env])),
        Err(Error::RecipientNotAllowed)
    );
    assert_eq!(
        recipients(&ctx, &Some(vec![&env, other.clone()])),
        Err(Error::RecipientNotAllowed)
    );
    assert_eq!(
        recipients(
            &ctx,
            &Some(vec![&env, other.clone(), ctx.request.recipient.clone()])
        ),
        Ok(ctx.request.recipient.clone())
    );
    assert_eq!(tokens(&ctx, &Some(vec![&env])), Err(Error::TokenNotAllowed));
    assert_eq!(
        tokens(&ctx, &Some(vec![&env, ctx.request.recipient.clone()])),
        Err(Error::TokenNotAllowed)
    );
}

#[test]
fn expiry_bounds_grant_and_request() {
    let env = Env::default();
    let mut ctx = fixture(&env);
    let now = ctx.request.now;
    assert_eq!(expiry(&ctx, &Some(now)), Err(Error::Expired));
    // A request cannot outlive the grant.
    assert_eq!(
        expiry(&ctx, &Some(ctx.request.expires_at - 1)),
        Err(Error::Expired)
    );
    ctx.request.expires_at = now;
    assert_eq!(expiry(&ctx, &Some(now + 10)), Err(Error::Expired));
}

#[test]
fn rules_encode_as_their_canonical_names_and_other_names_do_not_decode() {
    let env = Env::default();
    let symbol = |name: &str| -> Val { vec![&env, Symbol::new(&env, name)].into_val(&env) };
    for (i, rule) in ALL.into_iter().enumerate() {
        assert_eq!(position(rule), i);
        let name = std::format!("{rule:?}");
        assert_eq!(rule.to_xdr(&env), symbol(&name).to_xdr(&env));
        assert_eq!(Rule::try_from_val(&env, &symbol(&name)).ok(), Some(rule));
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
            Rule::try_from_val(&env, &symbol(name)).ok()
        }));
        assert!(matches!(decoded, Ok(None) | Err(_)));
    }
}

#[test]
fn grant_validation_rejects_only_negative_caps() {
    let env = Env::default();
    let grant = fixture(&env).grant;
    assert_eq!(Grant::default().validate(), Ok(()));
    for field in 0..4 {
        let mut bad = grant.clone();
        *[
            &mut bad.transaction_cap,
            &mut bad.spent_cap,
            &mut bad.day_spent_cap,
            &mut bad.day_total_cap,
        ][field] = Some(-1);
        assert_eq!(bad.validate(), Err(Error::InvalidParameter));
    }
    let mut zero = grant;
    zero.call_cap = Some(0);
    zero.spent_cap = Some(0);
    zero.recipients = Some(vec![&env]);
    assert_eq!(zero.validate(), Ok(()));
}
