//! Compile the authored custom policy against the allowit host backend without chain dependencies.
//! rustc --edition=2024 --crate-type=rlib --crate-name=allowit --cfg 'feature="std"' crates/allowit/src/lib.rs
//! rustc --edition=2024 --test --extern allowit=liballowit.rlib scripts/policy-smoke.rs
#[path = "../crates/custom-policy/policy/policy.rs"]
mod policy;
use allowit::prelude::*;
use allowit::{DAY, Error};

const NOW: u64 = 3 * DAY + 10;
fn context() -> AllowitEnv {
    let recipient = "GRECIPIENT".to_string();
    let asset = "CASSET".to_string();
    AllowitEnv {
        grant: Grant {
            transaction_cap: Some(10),
            spent_cap: Some(30),
            day_spent_cap: Some(20),
            day_total_cap: Some(20),
            call_cap: Some(2),
            recipients: Some(vec![recipient.clone()]),
            tokens: Some(vec![asset.clone()]),
            expiry: Some(NOW + 100),
        },
        state: AccountingHistory {
            calls: 1,
            spent: 10,
            day: NOW / DAY,
            day_spent: 10,
            day_total: 10,
            ..Default::default()
        },
        request: Request {
            operation: Operation::sep41_transfer,
            asset,
            recipient,
            amount: 10,
            now: NOW,
            expires_at: NOW + 50,
        },
    }
}
#[test]
fn approval_passes_with_exact_constraints() {
    let c = context();
    assert_eq!(policy::execute(&c), Ok(()));
    assert_eq!(
        allowit::transaction_cap(&c, &c.grant.transaction_cap),
        Ok(0)
    );
    assert_eq!(allowit::spent_cap(&c, &c.grant.spent_cap), Ok(20));
    assert_eq!(
        allowit::recipients(&c, &c.grant.recipients),
        Ok(c.request.recipient.clone())
    );
    assert_eq!(allowit::expiry(&c, &c.grant.expiry), Ok(50));
}
#[test]
fn approval_denies_unset_grant_fields() {
    let mut c = context();
    c.grant.tokens = None;
    assert_eq!(policy::execute(&c), Err(Error::MissingGrant));
    assert_eq!(allowit::preflight(&c, allowit::Rule::tokens), Ok(()));
}
#[test]
fn limits_boundary_denial_and_accounting() {
    let mut c = context();
    c.request.amount = 11;
    assert_eq!(policy::execute(&c), Err(Error::TransactionCapExceeded));
    let mut c = context();
    c.state.day_spent = 21;
    assert_eq!(policy::execute(&c), Err(Error::DaySpentCapExceeded));
    let mut c = context();
    c.state.unpriced = true;
    assert_eq!(policy::execute(&c), Err(Error::Unpriced));
    let mut c = context();
    c.state.day -= 1;
    assert_eq!(policy::execute(&c), Err(Error::InvalidState));
    let mut c = context();
    c.state.calls = 3;
    assert_eq!(policy::execute(&c), Err(Error::CallCapExceeded));
}
