//! Source and schema bindings. The shared portability vectors run in `allowit-policy-wallet`:
//! `src/portability_tests.rs` compares the std-only host smoke with the Soroban backend and the
//! custom, standard and simple contracts.
extern crate std;
use super::*;
use allowit::{AllowitGrant, AllowitOperation, AllowitRequest, AllowitStandardState};
use soroban_sdk::{Address, Bytes, Map, testutils::Address as _, vec};

#[test]
fn custom_runner_maps_the_policy_result() {
    let env = Env::default();
    let recipient = Address::generate(&env);
    let asset = Address::generate(&env);
    let mut state = Map::new(&env);
    let current = AllowitStandardState {
        spent: 5,
        ..Default::default()
    };
    current.write(&env, &mut state).unwrap();
    let ctx = AllowitContext {
        env: env.clone(),
        grant: AllowitGrant {
            transaction_cap: Some(10),
            spent_cap: Some(15),
            day_spent_cap: Some(10),
            day_total_cap: Some(10),
            call_cap: Some(1),
            recipients: Some(vec![&env, recipient.clone()]),
            tokens: Some(vec![&env, asset.clone()]),
            expiry: Some(100),
        },
        state,
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset,
            recipient,
            amount: 10,
            now: 10,
            expires_at: 20,
            spent_units: 10,
            gas_units: 0,
            unpriced: false,
        },
    };
    let rules = Vec::new(&env);
    assert_eq!(AllowitCustom::check(&ctx, &rules), Ok(()));
    let mut denied = ctx.clone();
    denied.grant.spent_cap = Some(14);
    assert_eq!(
        AllowitCustom::check(&denied, &rules),
        Err(AllowitWalletError::PolicyDenied)
    );
    let mut unset = ctx.clone();
    unset.grant.expiry = None;
    assert_eq!(
        AllowitCustom::check(&unset, &rules),
        Err(AllowitWalletError::InvalidGrant)
    );
}

#[test]
fn source_and_schema_bindings_match_their_exact_inputs() {
    let env = Env::default();
    let source = Bytes::from_slice(&env, include_bytes!("../policy/policy.rs"));
    assert_eq!(env.crypto().sha256(&source).to_array(), SOURCE_HASH);
    let schema = Bytes::from_slice(&env, allowit_wallet_protocol::ARGUMENT_SCHEMA_DESCRIPTOR);
    assert_eq!(
        env.crypto().sha256(&schema).to_array(),
        ARGUMENT_SCHEMA_HASH
    );
    let descriptor = core::str::from_utf8(allowit_wallet_protocol::ARGUMENT_SCHEMA_DESCRIPTOR);
    let operation = ADMITTED_OPERATION.replace("::", ".");
    assert!(descriptor.unwrap().contains(&operation));
}
