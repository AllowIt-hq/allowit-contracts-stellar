//! Compile the authored custom policies against the allowit host backend without chain dependencies.
//! rustc --edition=2024 -Coverflow-checks=on --crate-type=rlib --crate-name=allowit --cfg 'feature="std"' crates/allowit/src/lib.rs
//! rustc --edition=2024 -Coverflow-checks=on --test --extern allowit=liballowit.rlib scripts/policy-smoke.rs
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
use allowit::{AllowitEnv, AllowitRule, AllowitStandardState, AllowitStateMap, DAY};
use vectors::{Outcome, Vector};

const NOW: u64 = 3 * DAY + 10;
/// The state map of standard values `s`.
fn map(s: &AllowitStandardState) -> AllowitStateMap {
    let mut state = AllowitStateMap::new();
    s.write(&AllowitEnv::new(), &mut state).unwrap();
    state
}
/// Current state before a 10-unit priced transfer that passes every rule with exact headroom.
fn context() -> AllowitContext {
    let recipient = Address::new("GRECIPIENT");
    let asset = Address::new("CASSET");
    AllowitContext {
        env: AllowitEnv::new(),
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
        state: map(&AllowitStandardState {
            calls: 1,
            spent: 10,
            day: NOW / DAY,
            day_spent: 10,
            day_total: 10,
            ..Default::default()
        }),
        request: AllowitRequest {
            operation: AllowitOperation::sep41_transfer,
            asset,
            recipient,
            amount: 10,
            now: NOW,
            expires_at: NOW + 50,
            spent_units: 10,
            gas_units: 0,
            unpriced: false,
        },
    }
}
/// Edit the standard values of `c.state`.
fn edit(c: &mut AllowitContext, change: impl FnOnce(&mut AllowitStandardState)) {
    let mut s = AllowitStandardState::read(&c.env, &c.state).unwrap();
    change(&mut s);
    c.state = map(&s);
}
#[test]
fn approval_passes_with_exact_constraints() {
    let c = context();
    assert_eq!(policy::execute(&c), Ok(()));
    assert_eq!(
        allowit::transaction_cap(&c, &c.grant.transaction_cap),
        Ok(0)
    );
    assert_eq!(allowit::spent_cap(&c, &c.grant.spent_cap), Ok(10));
    assert_eq!(allowit::day_spent_cap(&c, &c.grant.day_spent_cap), Ok(0));
    assert_eq!(allowit::call_cap(&c, &c.grant.call_cap), Ok(0));
    assert_eq!(
        allowit::recipients(&c, &c.grant.recipients),
        Ok(c.request.recipient.clone())
    );
    assert_eq!(allowit::expiry(&c, &c.grant.expiry), Ok(100));
}
#[test]
fn approval_branch_policy_caps_deposits() {
    let mut c = context();
    edit(&mut c, |s| s.spent = 21);
    assert_eq!(branch::execute(&c), Ok(()));
    c.request.operation = AllowitOperation::sep56_deposit;
    assert_eq!(branch::execute(&c), Err(AllowitError::SpentCapExceeded));
}
#[test]
fn approval_denies_unset_grant_fields() {
    let mut c = context();
    c.grant.tokens = None;
    assert_eq!(policy::execute(&c), Err(AllowitError::MissingGrant));
    assert_eq!(allowit::preflight(&c, AllowitRule::tokens), Ok(()));
}
#[test]
fn approval_continues_after_a_caught_rule_error_and_post_flight_applies_its_writes() {
    let mut c = context();
    c.grant.day_spent_cap = Some(19);
    assert_eq!(catching::execute(&c), Ok(()));
    let next = allowit::post_flight(&c).unwrap();
    let mut after = c.clone();
    after.state = next;
    assert_eq!(
        allowit::get_state::<u64>(&after, vectors::OVER),
        Ok(Some(1))
    );
    assert_eq!(allowit::get_state::<u64>(&after, "calls"), Ok(Some(2)));
    // Twice counted, the policy returns the error and the run ends.
    allowit::set_state(&c, vectors::OVER, 2u64).unwrap();
    after.state = allowit::post_flight(&c).unwrap();
    after.env = AllowitEnv::new();
    assert_eq!(
        catching::execute(&after),
        Err(AllowitError::DaySpentCapExceeded)
    );
}
#[test]
fn limits_boundary_denial_and_accounting() {
    let mut c = context();
    c.request.amount = 11;
    assert_eq!(
        policy::execute(&c),
        Err(AllowitError::TransactionCapExceeded)
    );
    let mut c = context();
    edit(&mut c, |s| s.day_spent = 11);
    assert_eq!(policy::execute(&c), Err(AllowitError::DaySpentCapExceeded));
    let mut c = context();
    edit(&mut c, |s| s.unpriced = true);
    assert_eq!(policy::execute(&c), Err(AllowitError::Unpriced));
    let mut c = context();
    edit(&mut c, |s| s.day += 1);
    assert_eq!(policy::execute(&c), Err(AllowitError::InvalidState));
    let mut c = context();
    edit(&mut c, |s| s.calls = 2);
    assert_eq!(policy::execute(&c), Err(AllowitError::CallCapExceeded));
}
#[test]
fn approval_server_only_functions_compile_on_the_host_and_are_unsupported_until_filled() {
    let c = context();
    assert_eq!(
        allowit::price(&c, &c.request.asset, 1),
        Err(AllowitError::Unsupported)
    );
    assert_eq!(
        allowit::fetch(&c, "https://example.com"),
        Err(AllowitError::Unsupported)
    );
    assert_eq!(
        allowit::internet_search(&c, "q"),
        Err(AllowitError::Unsupported)
    );
    assert_eq!(
        allowit::marketplace_search(&c, "q"),
        Err(AllowitError::Unsupported)
    );
    assert_eq!(allowit::systemone(&c, "q"), Err(AllowitError::Unsupported));
    assert_eq!(
        allowit::request_screening(&c),
        Err(AllowitError::Unsupported)
    );
    assert_eq!(
        allowit::clear_systemone_context(&c),
        Err(AllowitError::Unsupported)
    );
}

/// Host address with StrKey-shaped text for each universe index.
fn address(index: usize) -> Address {
    Address::new(format!("CADDRESS{index}"))
}
fn host_context(v: &Vector) -> AllowitContext {
    let list = |items: &Option<Vec<usize>>| {
        items
            .as_ref()
            .map(|items| items.iter().map(|i| address(*i)).collect())
    };
    let env = AllowitEnv::new();
    let mut state = map(&AllowitStandardState {
        calls: v.calls,
        spent: v.spent,
        unpriced: v.unpriced,
        day: v.day,
        day_spent: v.day_spent,
        day_total: v.day_total,
        day_unpriced: v.day_unpriced,
    });
    if let Some(over) = v.over {
        state.insert(vectors::OVER.to_string(), allowit::AllowitVal::U64(over));
    }
    AllowitContext {
        env,
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
        state,
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
            spent_units: v.spent_units,
            gas_units: v.gas_units,
            unpriced: !v.priced,
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
/// `post_flight` of `c`, as `vectors::state_line`.
fn next(c: &AllowitContext) -> core::result::Result<String, u32> {
    let state = allowit::post_flight(c).map_err(|e| e as u32)?;
    let mut after = c.clone();
    after.state = state;
    let s = AllowitStandardState::read(&after.env, &after.state).unwrap();
    let over = allowit::get_state(&after, vectors::OVER).unwrap();
    Ok(vectors::state_line(
        s.calls,
        s.spent,
        s.unpriced,
        s.day,
        s.day_spent,
        s.day_total,
        s.day_unpriced,
        over,
    ))
}
fn host_outcome(v: &Vector) -> Outcome {
    let c = host_context(v);
    let g = &c.grant;
    let code = |e: AllowitError| e as u32;
    let index = |a: Address| {
        let i = (0..vectors::ADDRESSES).position(|i| address(i) == a);
        format!("@{}", i.unwrap())
    };
    let policy = policy::execute(&c).map_err(code);
    let branch = branch::execute(&c).map_err(code);
    let next_plain = next(&c);
    // The catching policy may write; post-flight consumes the writes in either case.
    let catching = catching::execute(&c).map_err(code);
    let catching_next = next(&c);
    Outcome {
        policy,
        branch,
        catching,
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
        next: next_plain,
        catching_next: catching.and(catching_next),
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
    assert_eq!(base.next, Ok("1/45/false/2/45/43/false/-".to_string()));
}
