use super::*;
use soroban_sdk::{Bytes, testutils::Address as _, vec};
fn fixture(env: &Env) -> (EngineRequest, EngineState) {
    let mut grant = allowit_wallet_protocol::Grant::new(env);
    for (name, value) in [
        ("daily_limit", 100u64),
        ("total_limit", 150),
        ("per_transfer", 100),
        ("max_calls", 3),
        ("expires_at", 999999),
    ] {
        grant.set(key(env, name), value.into_val(env));
    }
    grant.set(
        key(env, "token"),
        String::from_str(env, "USDC").into_val(env),
    );
    let recipient = Address::generate(env);
    grant.set(
        key(env, "recipients"),
        vec![env, recipient.clone()].into_val(env),
    );
    let mut spent = allowit_wallet_protocol::Spent::new(env);
    spent.set(
        key(env, "custom_bytes"),
        Bytes::from_slice(env, &[4, 5]).into_val(env),
    );
    (
        EngineRequest {
            wallet: Address::generate(env),
            agent: Address::generate(env),
            asset: Address::generate(env),
            token: String::from_str(env, "USDC"),
            decimals: 7,
            recipient,
            amount: 40,
            operation_id: BytesN::from_array(env, &[1; 32]),
            nonce: 0,
            deployment_version: 0,
            expires_at: 500,
            now: 100,
        },
        EngineState { grant, spent },
    )
}
fn amount(env: &Env, result: &EngineResult, name: &str) -> i128 {
    integer(env, &result.spent.get(key(env, name)).unwrap()).unwrap()
}
#[test]
fn daily_aliases_charge_once_and_recheck_stricter_bounds() {
    let env = Env::default();
    let (request, mut state) = fixture(&env);
    let first = daily_cap(env.clone(), request.clone(), state.clone()).unwrap();
    assert!(first.approval);
    assert_eq!(amount(&env, &first, "daily"), 40);
    state.spent = first.spent;
    let again = cap_per_day(
        env.clone(),
        request.clone(),
        state.clone(),
        40,
        String::from_str(&env, "USDC"),
    )
    .unwrap();
    assert!(again.approval);
    assert_eq!(again.spent, state.spent);
    let denied = cap_per_day(
        env.clone(),
        request.clone(),
        state.clone(),
        39,
        String::from_str(&env, "USDC"),
    )
    .unwrap();
    assert!(!denied.approval);
    assert_eq!(denied.spent, state.spent);
    let mut next = request;
    next.operation_id = BytesN::from_array(&env, &[2; 32]);
    next.amount = 60;
    let full = daily_cap(env.clone(), next.clone(), state.clone()).unwrap();
    assert!(full.approval);
    assert_eq!(amount(&env, &full, "daily"), 100);
    state.spent = full.spent;
    next.operation_id = BytesN::from_array(&env, &[3; 32]);
    next.amount = 1;
    let denied = daily_cap(env.clone(), next, state.clone()).unwrap();
    assert!(!denied.approval);
    assert_eq!(denied.spent, state.spent);
}
#[test]
fn selected_checks_update_distinct_fields_and_preserve_unknown_values() {
    let env = Env::default();
    let (request, mut state) = fixture(&env);
    let total = total_cap(env.clone(), request.clone(), state.clone()).unwrap();
    assert_eq!(amount(&env, &total, "total"), 40);
    state.spent = total.spent;
    let calls = call_cap(env.clone(), request.clone(), state.clone()).unwrap();
    state.spent = calls.spent;
    let calls = call_cap(env.clone(), request.clone(), state.clone()).unwrap();
    assert_eq!(calls.spent, state.spent);
    assert_eq!(
        u64::try_from_val(&env, &calls.spent.get(key(&env, "calls")).unwrap()).unwrap(),
        1
    );
    assert_eq!(
        Bytes::try_from_val(&env, &calls.spent.get(key(&env, "custom_bytes")).unwrap()).unwrap(),
        Bytes::from_slice(&env, &[4, 5])
    );
    assert!(
        recipient(env.clone(), request.clone(), state.clone())
            .unwrap()
            .approval
    );
    assert!(
        token(env.clone(), request.clone(), state.clone())
            .unwrap()
            .approval
    );
    let mut expired = request.clone();
    expired.expires_at = expired.now;
    assert!(
        !expiry(env.clone(), expired, state.clone())
            .unwrap()
            .approval
    );
    assert!(expiry(env.clone(), request, state).unwrap().approval);
}
#[test]
fn daily_rollover_is_explicit_and_regression_denies() {
    let env = Env::default();
    let (mut request, mut state) = fixture(&env);
    state.spent = daily_cap(env.clone(), request.clone(), state.clone())
        .unwrap()
        .spent;
    request.now = DAY;
    request.expires_at = DAY + 1;
    request.operation_id = BytesN::from_array(&env, &[2; 32]);
    request.amount = 5;
    let next = daily_cap(env.clone(), request.clone(), state.clone()).unwrap();
    assert_eq!(amount(&env, &next, "daily"), 5);
    state.spent = next.spent;
    request.now = 0;
    assert_eq!(daily_cap(env, request, state), Err(Error::InvalidState));
}
#[test]
fn optional_keys_do_not_activate_and_invalid_selected_values_fail() {
    let env = Env::default();
    let (request, mut state) = fixture(&env);
    state.grant.remove(key(&env, "daily_limit"));
    assert!(
        transaction_cap(env.clone(), request.clone(), state.clone())
            .unwrap()
            .approval
    );
    assert_eq!(
        daily_cap(env.clone(), request.clone(), state.clone()),
        Err(Error::InvalidParameter)
    );
    state
        .grant
        .set(key(&env, "daily_limit"), true.into_val(&env));
    assert_eq!(
        daily_cap(env.clone(), request.clone(), state.clone()),
        Err(Error::InvalidParameter)
    );
    state
        .grant
        .set(key(&env, "daily_limit"), 100u64.into_val(&env));
    state.spent.set(key(&env, "daily"), (-1i128).into_val(&env));
    assert_eq!(
        daily_cap(env.clone(), request.clone(), state.clone()),
        Err(Error::InvalidState)
    );
    state
        .spent
        .set(key(&env, "daily"), i128::MAX.into_val(&env));
    assert_eq!(daily_cap(env, request, state), Err(Error::Overflow));
}
#[test]
fn predicates_keep_false_distinct_from_error_and_dispatch_is_exact() {
    let env = Env::default();
    let (request, state) = fixture(&env);
    let denied = amount_at_most(
        env.clone(),
        request.clone(),
        state.clone(),
        39,
        String::from_str(&env, "USDC"),
    )
    .unwrap();
    assert!(!denied.approval);
    assert_eq!(denied.spent, state.spent);
    assert!(
        !amount_at_most(
            env.clone(),
            request.clone(),
            state.clone(),
            0,
            String::from_str(&env, "USDC")
        )
        .unwrap()
        .approval
    );
    assert_eq!(
        amount_at_most(
            env.clone(),
            request.clone(),
            state.clone(),
            39,
            String::from_str(&env, "XLM")
        ),
        Err(Error::InvalidParameter)
    );
    assert_eq!(
        check(&env, request.clone(), state.clone(), "unknown", vec![&env]),
        Err(Error::InvalidParameter)
    );
    assert_eq!(
        check(
            &env,
            request.clone(),
            state.clone(),
            "daily_cap",
            vec![&env, true.into_val(&env)]
        ),
        Err(Error::InvalidParameter)
    );
    assert_eq!(
        check(
            &env,
            request,
            state,
            "cap_per_day",
            vec![
                &env,
                true.into_val(&env),
                String::from_str(&env, "USDC").into_val(&env)
            ]
        ),
        Err(Error::InvalidParameter)
    );
}
