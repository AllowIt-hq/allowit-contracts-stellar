//! Compile the authored custom policies against the allowit host backend without chain dependencies.
//! rustc --edition=2024 --crate-type=rlib --crate-name=allowit --cfg 'feature="std"' crates/allowit/src/lib.rs
//! rustc --edition=2024 --test --extern allowit=liballowit.rlib scripts/policy-smoke.rs
//! `cargo test` in `allowit-policy-wallet` runs these commands, then compares the
//! `vectors_print_host_outcomes` lines with the Soroban backend and the wallet contracts.
#[path = "../crates/custom-policy/src/branch_policy.rs"]
mod branch;
#[path = "../crates/custom-policy/src/catching_policy.rs"]
mod catching;
#[path = "../crates/custom-policy/policy/policy.rs"]
mod policy;
#[path = "policy-vectors.rs"]
mod vectors;
use allowit::prelude::*;
use allowit::{AllowitEnv, AllowitError, AllowitRule, DAY};
use vectors::{Outcome, Vector};

const NOW: u64 = 3 * DAY + 10;
fn context() -> AllowitContext {
    let recipient = "GRECIPIENT".to_string();
    let asset = "CASSET".to_string();
    AllowitContext {
        env: AllowitEnv::default(),
        grant: AllowitGrant {
            transaction_cap: Some(10),
            spent_cap: Some(30),
            day_spent_cap: Some(20),
            day_total_cap: Some(20),
            call_cap: Some(2),
            recipients: Some(vec![recipient.clone()]),
            tokens: Some(vec![asset.clone()]),
            expiry: Some(NOW + 100),
        },
        state: AllowitAccountingHistory {
            calls: 1,
            spent: 10,
            day: NOW / DAY,
            day_spent: 10,
            day_total: 10,
            ..Default::default()
        },
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset,
            recipient,
            amount: 10,
            now: NOW,
            expires_at: NOW + 50,
        },
    }
}
/// Run a policy as the offchain server does, on a context with a new host environment.
fn run(c: &AllowitContext, execute: fn(&AllowitContext) -> allowit::Result) -> allowit::Result {
    let c = AllowitContext {
        env: AllowitEnv::default(),
        ..c.clone()
    };
    allowit::run(&c, execute)
}
#[test]
fn approval_passes_with_exact_constraints() {
    let c = context();
    assert_eq!(run(&c, policy::execute), Ok(()));
    assert_eq!(
        allowit::transaction_cap(&c, &c.grant.transaction_cap),
        Ok(0)
    );
    assert_eq!(allowit::spent_cap(&c, &c.grant.spent_cap), Ok(20));
    assert_eq!(
        allowit::recipients(&c, &c.grant.recipients),
        Ok(c.request.recipient.clone())
    );
    assert_eq!(allowit::expiry(&c, &c.grant.expiry), Ok(100));
}
#[test]
fn approval_branch_policy_caps_deposits() {
    let mut c = context();
    c.state.spent = 31;
    assert_eq!(run(&c, branch::execute), Ok(()));
    c.request.operation = AllowitOperation::sep56_deposit;
    assert_eq!(
        run(&c, branch::execute),
        Err(AllowitError::SpentCapExceeded)
    );
}
#[test]
fn approval_denies_unset_grant_fields() {
    let mut c = context();
    c.grant.tokens = None;
    assert_eq!(run(&c, policy::execute), Err(AllowitError::MissingGrant));
    assert_eq!(allowit::preflight(&c, AllowitRule::tokens), Ok(()));
}
#[test]
fn approval_denies_a_caught_rule_failure() {
    let mut c = context();
    assert_eq!(run(&c, catching::execute), Ok(()));
    c.state.spent = 31;
    assert_eq!(catching::execute(&c), Ok(()));
    assert_eq!(
        run(&c, catching::execute),
        Err(AllowitError::SpentCapExceeded)
    );
}
#[test]
fn limits_boundary_denial_and_accounting() {
    let mut c = context();
    c.request.amount = 11;
    assert_eq!(
        run(&c, policy::execute),
        Err(AllowitError::TransactionCapExceeded)
    );
    let mut c = context();
    c.state.day_spent = 21;
    assert_eq!(
        run(&c, policy::execute),
        Err(AllowitError::DaySpentCapExceeded)
    );
    let mut c = context();
    c.state.unpriced = true;
    assert_eq!(run(&c, policy::execute), Err(AllowitError::Unpriced));
    let mut c = context();
    c.state.day -= 1;
    assert_eq!(run(&c, policy::execute), Err(AllowitError::InvalidState));
    let mut c = context();
    c.state.calls = 3;
    assert_eq!(run(&c, policy::execute), Err(AllowitError::CallCapExceeded));
}

/// Host StrKey-shaped text of each universe address.
fn address(index: usize) -> String {
    format!("CADDRESS{index}")
}
fn host_context(v: &Vector) -> AllowitContext {
    let list = |items: &Option<Vec<usize>>| {
        items
            .as_ref()
            .map(|items| items.iter().map(|i| address(*i)).collect())
    };
    AllowitContext {
        env: AllowitEnv::default(),
        grant: AllowitGrant {
            transaction_cap: v.caps[0],
            spent_cap: v.caps[1],
            day_spent_cap: v.caps[2],
            day_total_cap: v.caps[3],
            call_cap: v.call_cap,
            recipients: list(&v.recipients),
            tokens: list(&v.tokens),
            expiry: v.expiry,
        },
        state: AllowitAccountingHistory {
            calls: v.calls,
            spent: v.spent,
            unpriced: v.unpriced,
            day: v.day,
            day_spent: v.day_spent,
            day_total: v.day_total,
            day_unpriced: v.day_unpriced,
        },
        request: AllowitRequest {
            operation: if v.deposit {
                AllowitOperation::sep56_deposit
            } else {
                AllowitOperation::sep41_transfer
            },
            asset: address(v.asset),
            recipient: address(v.recipient),
            amount: v.amount,
            now: v.now,
            expires_at: v.expires_at,
        },
    }
}
/// Every canonical rule in Grant field order.
const RULES: [AllowitRule; 8] = [
    AllowitRule::transaction_cap,
    AllowitRule::spent_cap,
    AllowitRule::day_spent_cap,
    AllowitRule::day_total_cap,
    AllowitRule::call_cap,
    AllowitRule::recipients,
    AllowitRule::tokens,
    AllowitRule::expiry,
];
fn host_outcome(v: &Vector) -> Outcome {
    let c = host_context(v);
    let g = &c.grant;
    let code = |e: AllowitError| e as u32;
    let index = |a: Address| {
        let i = (0..vectors::ADDRESSES).position(|i| address(i) == a);
        format!("@{}", i.unwrap())
    };
    Outcome {
        policy: run(&c, policy::execute).map_err(code),
        branch: run(&c, branch::execute).map_err(code),
        catching: run(&c, catching::execute).map_err(code),
        rules: vec![
            allowit::transaction_cap(&c, &g.transaction_cap).map(|v| v.to_string()),
            allowit::spent_cap(&c, &g.spent_cap).map(|v| v.to_string()),
            allowit::day_spent_cap(&c, &g.day_spent_cap).map(|v| v.to_string()),
            allowit::day_total_cap(&c, &g.day_total_cap).map(|v| v.to_string()),
            allowit::call_cap(&c, &g.call_cap).map(|v| v.to_string()),
            allowit::recipients(&c, &g.recipients).map(index),
            allowit::tokens(&c, &g.tokens).map(index),
            allowit::expiry(&c, &g.expiry).map(|v| v.to_string()),
        ]
        .into_iter()
        .map(|r| r.map_err(code))
        .collect(),
        preflight: RULES
            .into_iter()
            .map(|rule| allowit::preflight(&c, rule).map_err(code))
            .collect(),
    }
}
/// Print the host outcome of every shared vector for the contract portability test.
#[test]
fn vectors_print_host_outcomes() {
    let all = vectors::vectors();
    for v in &all {
        println!("{}", host_outcome(v).line(v.name));
    }
    let base = host_outcome(&all[0]);
    assert_eq!(base.policy, Ok(()));
    assert_eq!(base.preflight, vec![Ok(()); 8]);
}
