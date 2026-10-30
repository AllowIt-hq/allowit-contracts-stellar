use super::*;
use allowit::{AccountingHistory, Grant, Operation, Request};
use soroban_sdk::{testutils::Address as _, vec};
fn fixture(env: &Env) -> AllowitEnv {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    AllowitEnv {
        grant: Grant {
            transaction_cap: Some(100),
            spent_cap: Some(45),
            day_spent_cap: Some(50),
            day_total_cap: Some(100),
            call_cap: Some(3),
            recipients: Some(vec![env, recipient.clone()]),
            tokens: Some(vec![env, asset.clone()]),
            expiry: Some(1_000),
        },
        state: AccountingHistory {
            calls: 1,
            spent: 45,
            day_spent: 45,
            day_total: 43,
            ..Default::default()
        },
        request: Request {
            operation: Operation::sep41_transfer,
            asset,
            recipient,
            amount: 40,
            now: 100,
            expires_at: 500,
        },
    }
}
#[test]
fn native_contract_wrapper_matches_the_bundled_rule() {
    let env = Env::default();
    let ctx = fixture(&env);
    assert_eq!(
        Engine::day_total_cap(env.clone(), ctx.clone()),
        allowit::day_total_cap(&ctx, &ctx.grant.day_total_cap)
    );
    assert_eq!(Engine::day_total_cap(env, ctx), Ok(57));
}
#[test]
fn engine_metadata_is_pure_release_data() {
    let env = Env::default();
    assert_eq!(Engine::engine_version(env.clone()), 2);
    assert!(env.auths().is_empty());
}

#[test]
fn compiled_engine_returns_bundled_pass_values_and_rule_errors() {
    const WASM: &[u8] =
        include_bytes!("../../../target/wasm32v1-none/release/allowit_wallet_engine.wasm");
    let env = Env::default();
    let id = env.register(WASM, ());
    let client = EngineClient::new(&env, &id);
    let mut ctx = fixture(&env);
    assert_eq!(client.transaction_cap(&ctx), 60);
    assert_eq!(client.spent_cap(&ctx), 0);
    assert_eq!(client.day_spent_cap(&ctx), 5);
    assert_eq!(client.day_total_cap(&ctx), 57);
    assert_eq!(client.call_cap(&ctx), 2);
    assert_eq!(client.recipients(&ctx), ctx.request.recipient);
    assert_eq!(client.tokens(&ctx), ctx.request.asset);
    assert_eq!(client.expiry(&ctx), 400);
    ctx.grant.day_total_cap = Some(42);
    assert_eq!(
        client.try_day_total_cap(&ctx),
        Err(Ok(Error::DayTotalCapExceeded))
    );
    ctx.grant.spent_cap = None;
    assert_eq!(client.try_spent_cap(&ctx), Err(Ok(Error::MissingGrant)));
}
