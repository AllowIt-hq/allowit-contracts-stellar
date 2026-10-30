use super::*;
use allowit_wallet_protocol::{ExpenseBounds, Grant, Spent};
use soroban_sdk::{Bytes, testutils::Address as _, vec};
fn fixture(env: &Env) -> (EngineRequest, EngineState) {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    let mut grant = Grant::new(env);
    for (name, value) in [
        ("spent_cap", 1000i128),
        ("day_spent_cap", 1000),
        ("day_total_cap", 1000),
        ("transaction_cap", 100),
    ] {
        grant.set(key(env, name), value.into_val(env));
    }
    grant.set(key(env, "call_cap"), 3u64.into_val(env));
    grant.set(key(env, "expiry"), 999999u64.into_val(env));
    grant.set(key(env, "tokens"), vec![env, asset.clone()].into_val(env));
    grant.set(
        key(env, "recipients"),
        vec![env, recipient.clone()].into_val(env),
    );
    let e = ExpenseBounds {
        asset: asset.clone(),
        decimals: 7,
        gas_units: 3,
        conversion_units: 2,
        spent_units: 5,
        max_fee_stroops: 3,
        observed_ledger: 1,
        day: 0,
    };
    let request = EngineRequest {
        history: allowit_wallet_protocol::AccountingHistory {
            calls: 1,
            spent: 5,
            day_spent: 5,
            day_total: 43,
            ..Default::default()
        },
        expense: Some(e.to_xdr(env)),
        wallet: Address::generate(env),
        agent: Address::generate(env),
        asset,
        token: String::from_str(env, "USDC"),
        decimals: 7,
        recipient,
        amount: 40,
        operation_id: BytesN::from_array(env, &[1; 32]),
        nonce: 0,
        deployment_version: 0,
        expires_at: 500,
        now: 100,
    };
    let mut spent = Spent::new(env);
    spent.set(
        key(env, "custom_bytes"),
        Bytes::from_slice(env, &[4, 5]).into_val(env),
    );
    (request, EngineState { grant, spent })
}
fn cost(env: &Env, r: &EngineRequest) -> ExpenseBounds {
    ExpenseBounds::from_xdr(env, r.expense.as_ref().unwrap()).unwrap()
}
fn amount(env: &Env, s: &Spent, k: &str) -> i128 {
    integer(env, &s.get(key(env, k)).unwrap()).unwrap()
}
#[test]
fn split_caps_chain_and_repeat_without_suppressing_other_counters() {
    let env = Env::default();
    let (r, mut s) = fixture(&env);
    for f in [spent_cap, day_spent_cap, day_total_cap] {
        let x = f(env.clone(), r.clone(), s.clone()).unwrap();
        assert!(x.approval);
        s.spent = x.spent;
    }
    assert_eq!(amount(&env, &s.spent, "spent"), 5);
    assert_eq!(amount(&env, &s.spent, "day_spent"), 5);
    assert_eq!(amount(&env, &s.spent, "day_total"), 43);
    for f in [spent_cap, day_spent_cap, day_total_cap] {
        let x = f(env.clone(), r.clone(), s.clone()).unwrap();
        assert!(x.approval);
        assert_eq!(x.spent, s.spent);
    }
    assert_eq!(
        Bytes::try_from_val(&env, &s.spent.get(key(&env, "custom_bytes")).unwrap()).unwrap(),
        Bytes::from_slice(&env, &[4, 5])
    );
}
#[test]
fn repeated_operation_cannot_rewrite_expense_or_gross_facts() {
    let env = Env::default();
    let (mut r, mut s) = fixture(&env);
    for f in [spent_cap, day_spent_cap, day_total_cap] {
        s.spent = f(env.clone(), r.clone(), s.clone()).unwrap().spent;
    }
    let mut e = cost(&env, &r);
    e.gas_units = 4;
    e.max_fee_stroops = 4;
    e.spent_units = 6;
    r.expense = Some(e.to_xdr(&env));
    for f in [spent_cap, day_spent_cap, day_total_cap] {
        assert_eq!(
            f(env.clone(), r.clone(), s.clone()),
            Err(Error::InvalidState)
        );
    }
}
#[test]
fn daily_rollover_preserves_lifetime_expenses_and_rejects_clock_regression() {
    let env = Env::default();
    let (mut r, mut s) = fixture(&env);
    for f in [spent_cap, day_spent_cap, day_total_cap] {
        s.spent = f(env.clone(), r.clone(), s.clone()).unwrap().spent;
    }
    r.now += DAY;
    r.history.day += 1;
    r.history.spent += 5;
    r.operation_id = BytesN::from_array(&env, &[2; 32]);
    let mut e = cost(&env, &r);
    e.day = r.now / DAY;
    r.expense = Some(e.to_xdr(&env));
    for f in [spent_cap, day_spent_cap, day_total_cap] {
        s.spent = f(env.clone(), r.clone(), s.clone()).unwrap().spent;
    }
    assert_eq!(amount(&env, &s.spent, "spent"), 10);
    assert_eq!(amount(&env, &s.spent, "day_spent"), 5);
    assert_eq!(amount(&env, &s.spent, "day_total"), 43);
    r.now -= DAY;
    let mut e = cost(&env, &r);
    e.day = r.now / DAY;
    r.expense = Some(e.to_xdr(&env));
    assert_eq!(day_spent_cap(env.clone(), r, s), Err(Error::InvalidState));
}
#[test]
fn zero_cost_cap_and_missing_or_invalid_facts_fail_closed() {
    let env = Env::default();
    let (mut r, mut s) = fixture(&env);
    r.expense = None;
    for f in [spent_cap, day_spent_cap, day_total_cap] {
        assert_eq!(
            f(env.clone(), r.clone(), s.clone()),
            Err(Error::InvalidParameter)
        );
    }
    let (mut r, _) = fixture(&env);
    let mut e = cost(&env, &r);
    e.gas_units = 0;
    e.max_fee_stroops = 0;
    e.conversion_units = 0;
    e.spent_units = 0;
    r.expense = Some(e.to_xdr(&env));
    r.history.spent = 0;
    s.grant.set(key(&env, "spent_cap"), 0i128.into_val(&env));
    assert!(
        spent_cap(env.clone(), r.clone(), s.clone())
            .unwrap()
            .approval
    );
    let mut e = cost(&env, &r);
    e.spent_units = 1;
    r.history.spent = 1;
    r.expense = Some(e.to_xdr(&env));
    assert!(!spent_cap(env.clone(), r, s).unwrap().approval);
}
#[test]
fn canonical_allowlists_use_exact_addresses_and_never_coerce_labels() {
    let env = Env::default();
    let (mut r, mut s) = fixture(&env);
    assert!(tokens(env.clone(), r.clone(), s.clone()).unwrap().approval);
    assert!(
        recipients(env.clone(), r.clone(), s.clone())
            .unwrap()
            .approval
    );
    r.asset = Address::generate(&env);
    assert!(!tokens(env.clone(), r.clone(), s.clone()).unwrap().approval);
    s.grant.set(
        key(&env, "tokens"),
        vec![&env, String::from_str(&env, "USDC")].into_val(&env),
    );
    assert_eq!(tokens(env.clone(), r, s), Err(Error::InvalidParameter));
}
#[test]
fn aliases_and_unselected_keys_create_no_hidden_rule() {
    let env = Env::default();
    let (r, s) = fixture(&env);
    for name in [
        "daily_cap",
        "total_cap",
        "recipient",
        "token",
        "cap_per_transaction",
        "cap_per_day",
        "recipient_is",
        "asset_label",
        "actions",
        "amount_at_most",
    ] {
        assert!(validate_rule(&env, &soroban_sdk::Symbol::new(&env, name), &s.grant).is_err());
        assert_eq!(
            check(&env, r.clone(), s.clone(), name, Vec::new(&env)),
            Err(Error::InvalidParameter)
        );
    }
    assert!(
        transaction_cap(env.clone(), r.clone(), s.clone())
            .unwrap()
            .approval
    );
    let mut bad = s.clone();
    bad.grant.set(key(&env, "spent_cap"), true.into_val(&env));
    assert!(
        transaction_cap(env.clone(), r.clone(), bad.clone())
            .unwrap()
            .approval
    );
    assert_eq!(spent_cap(env.clone(), r, bad), Err(Error::InvalidParameter));
}
#[test]
fn selected_cap_boundaries_and_authored_map_cannot_rewrite_protected_history() {
    let env = Env::default();
    let (r, mut s) = fixture(&env);
    s.grant.set(key(&env, "spent_cap"), 5i128.into_val(&env));
    let a = spent_cap(env.clone(), r.clone(), s.clone()).unwrap();
    assert!(a.approval);
    s.spent = a.spent;
    s.grant.set(key(&env, "spent_cap"), 4i128.into_val(&env));
    let denied = spent_cap(env.clone(), r.clone(), s.clone()).unwrap();
    assert!(!denied.approval);
    assert_eq!(denied.spent, s.spent);
    s.grant
        .set(key(&env, "spent_cap"), i128::MAX.into_val(&env));
    s.spent.set(key(&env, "spent"), i128::MAX.into_val(&env));
    let mut next = r;
    next.operation_id = BytesN::from_array(&env, &[9; 32]);
    // A forged business counter does not become the protected custody history.
    let checked = spent_cap(env.clone(), next, s).unwrap();
    assert!(checked.approval);
    assert_eq!(amount(&env, &checked.spent, "spent"), 5);
}

#[test]
fn normalized_positive_gas_keeps_asset_scale_and_xlm_identity_checks() {
    let env = Env::default();
    let (mut request, state) = fixture(&env);
    let mut e = cost(&env, &request);
    e.max_fee_stroops = 100;
    request.expense = Some(e.clone().to_xdr(&env));
    assert!(
        spent_cap(env.clone(), request.clone(), state.clone())
            .unwrap()
            .approval
    );
    for zero_fee in [false, true] {
        let mut invalid = e.clone();
        if zero_fee {
            invalid.max_fee_stroops = 0
        } else {
            invalid.gas_units = 0
        };
        request.expense = Some(invalid.to_xdr(&env));
        assert_eq!(
            spent_cap(env.clone(), request.clone(), state.clone()),
            Err(Error::InvalidParameter)
        );
    }
    request.asset = env
        .deployer()
        .with_stellar_asset(Bytes::from_array(&env, &[0; 4]))
        .deployed_address();
    e.asset = request.asset.clone();
    request.expense = Some(e.to_xdr(&env));
    assert_eq!(
        spent_cap(env.clone(), request, state),
        Err(Error::InvalidParameter)
    );
}
