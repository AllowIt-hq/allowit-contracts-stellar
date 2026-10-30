//! Source and schema bindings. The shared portability vectors run in `allowit-policy-wallet`:
//! `src/portability_tests.rs` compares the std-only host smoke with the Soroban backend and the
//! custom, standard and simple contracts.
extern crate std;
use super::*;
use allowit::{
    AllowitAccountingHistory, AllowitError, AllowitGrant, AllowitOperation, AllowitRequest,
};
use soroban_sdk::{Address, Bytes, testutils::Address as _, vec};

#[test]
fn custom_runner_maps_the_policy_result_and_reads_only_its_own_rule_failures() {
    let env = Env::default();
    let recipient = Address::generate(&env);
    let asset = Address::generate(&env);
    let ctx = AllowitContext {
        env: env.clone(),
        grant: AllowitGrant {
            transaction_cap: Some(10),
            spent_cap: Some(10),
            day_spent_cap: Some(10),
            day_total_cap: Some(10),
            call_cap: Some(1),
            recipients: Some(vec![&env, recipient.clone()]),
            tokens: Some(vec![&env, asset.clone()]),
            expiry: Some(100),
        },
        state: AllowitAccountingHistory {
            calls: 1,
            spent: 10,
            day_spent: 10,
            day_total: 10,
            ..Default::default()
        },
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset,
            recipient,
            amount: 10,
            now: 10,
            expires_at: 20,
        },
    };
    let rules = Vec::new(&env);
    assert_eq!(AllowitCustom::check(&ctx, &rules), Ok(()));
    let mut denied = ctx.clone();
    denied.grant.spent_cap = Some(9);
    assert_eq!(
        AllowitCustom::check(&denied, &rules),
        Err(AllowitWalletError::PolicyDenied)
    );
    assert_eq!(
        allowit::run(&denied, policy::execute),
        Err(AllowitError::SpentCapExceeded)
    );
    // A rule failure outside the policy run, earlier in the same invocation, does not deny it.
    assert!(allowit::spent_cap(&denied, &denied.grant.spent_cap).is_err());
    assert_eq!(AllowitCustom::check(&ctx, &rules), Ok(()));
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
