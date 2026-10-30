use super::*;
use allowit::{
    AllowitAccountingHistory, AllowitGrant, AllowitOperation, AllowitRequest, AllowitRule,
};
use soroban_sdk::{testutils::Address as _, vec};
fn fixture(env: &Env) -> AllowitContext {
    let asset = Address::generate(env);
    let recipient = Address::generate(env);
    AllowitContext {
        grant: AllowitGrant {
            transaction_cap: Some(100),
            spent_cap: Some(45),
            day_spent_cap: Some(50),
            day_total_cap: Some(100),
            call_cap: Some(3),
            recipients: Some(vec![env, recipient.clone()]),
            tokens: Some(vec![env, asset.clone()]),
            expiry: Some(1_000),
        },
        state: AllowitAccountingHistory {
            calls: 1,
            spent: 45,
            day_spent: 45,
            day_total: 43,
            ..Default::default()
        },
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset,
            recipient,
            amount: 40,
            now: 100,
            expires_at: 500,
        },
    }
}
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
    let c = &ctx;
    let g = &c.grant;
    // The exhaustive match fails to compile when a rule lacks its engine method.
    for rule in ALL {
        match rule {
            AllowitRule::transaction_cap => {
                let v = allowit::transaction_cap(c, &g.transaction_cap);
                assert_eq!((client.transaction_cap(c), v), (60, Ok(60)));
            }
            AllowitRule::spent_cap => {
                let v = allowit::spent_cap(c, &g.spent_cap);
                assert_eq!((client.spent_cap(c), v), (0, Ok(0)));
            }
            AllowitRule::day_spent_cap => {
                let v = allowit::day_spent_cap(c, &g.day_spent_cap);
                assert_eq!((client.day_spent_cap(c), v), (5, Ok(5)));
            }
            AllowitRule::day_total_cap => {
                let v = allowit::day_total_cap(c, &g.day_total_cap);
                assert_eq!((client.day_total_cap(c), v), (57, Ok(57)));
            }
            AllowitRule::call_cap => {
                let v = allowit::call_cap(c, &g.call_cap);
                assert_eq!((client.call_cap(c), v), (2, Ok(2)));
            }
            AllowitRule::recipients => {
                let v = allowit::recipients(c, &g.recipients);
                assert_eq!(Ok(client.recipients(c)), v);
                assert_eq!(v, Ok(c.request.recipient.clone()));
            }
            AllowitRule::tokens => {
                let v = allowit::tokens(c, &g.tokens);
                assert_eq!(Ok(client.tokens(c)), v);
                assert_eq!(v, Ok(c.request.asset.clone()));
            }
            AllowitRule::expiry => {
                let v = allowit::expiry(c, &g.expiry);
                assert_eq!((client.expiry(c), v), (900, Ok(900)));
            }
        }
    }
    ctx.grant.day_total_cap = Some(42);
    assert_eq!(
        client.try_day_total_cap(&ctx),
        Err(Ok(AllowitError::DayTotalCapExceeded))
    );
    ctx.grant.spent_cap = None;
    assert_eq!(
        client.try_spent_cap(&ctx),
        Err(Ok(AllowitError::MissingGrant))
    );
}
