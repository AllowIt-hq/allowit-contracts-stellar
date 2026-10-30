use super::*;
use allowit_wallet_protocol::{Grant, Spent};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, BytesN, Env, IntoVal, String, testutils::Address as _};
fn fixture(env: &Env) -> (EngineRequest, EngineState) {
    let mut grant = Grant::new(env);
    grant.set(String::from_str(env, "day_total_cap"), 100u64.into_val(env));
    let asset = Address::generate(env);
    (
        EngineRequest {
            history: allowit_wallet_protocol::AccountingHistory {
                calls: 1,
                spent: 5,
                day_spent: 5,
                day_total: 43,
                ..Default::default()
            },
            expense: Some(
                allowit_wallet_protocol::ExpenseBounds {
                    asset: asset.clone(),
                    decimals: 7,
                    gas_units: 0,
                    conversion_units: 0,
                    spent_units: 40,
                    max_fee_stroops: 0,
                    observed_ledger: 1,
                    day: 0,
                }
                .to_xdr(env),
            ),
            wallet: Address::generate(env),
            agent: Address::generate(env),
            asset: asset.clone(),
            token: String::from_str(env, "USDC"),
            decimals: 7,
            recipient: Address::generate(env),
            amount: 40,
            operation_id: BytesN::from_array(env, &[1; 32]),
            nonce: 0,
            deployment_version: 0,
            expires_at: 500,
            now: 100,
        },
        EngineState {
            grant,
            spent: Spent::new(env),
        },
    )
}
#[test]
fn native_contract_wrapper_matches_the_bundled_rule() {
    let env = Env::default();
    let (request, state) = fixture(&env);
    assert_eq!(
        Engine::day_total_cap(env.clone(), request.clone(), state.clone()),
        allowit_policy_rules::day_total_cap(env, request, state)
    );
}
#[test]
fn engine_metadata_is_pure_release_data() {
    let env = Env::default();
    assert_eq!(Engine::engine_version(env.clone()), 1);
    assert!(env.auths().is_empty());
}

#[test]
fn compiled_engine_matches_bundled_code_and_repeated_daily_checks_charge_once() {
    const WASM: &[u8] =
        include_bytes!("../../../target/wasm32v1-none/release/allowit_wallet_engine.wasm");
    let env = Env::default();
    let id = env.register(WASM, ());
    let client = allowit_wallet_protocol::EngineClient::new(&env, &id);
    let (request, mut state) = fixture(&env);
    let bundled =
        allowit_policy_rules::day_total_cap(env.clone(), request.clone(), state.clone()).unwrap();
    let remote = client.day_total_cap(&request, &state);
    assert_eq!(remote, bundled);
    state.spent = remote.spent;
    let repeated = client.day_total_cap(&request, &state);
    assert!(repeated.approval);
    assert_eq!(repeated.spent, state.spent);
    state.grant.set(
        String::from_str(&env, "day_total_cap"),
        39i128.into_val(&env),
    );
    let stricter = client.day_total_cap(&request, &state);
    assert!(!stricter.approval);
    assert_eq!(stricter.spent, state.spent);
}
