// Compile the production portable policy without chain dependencies.
#[path = "../policy/policy_api.rs"]
mod policy_api;
#[path = "../policy/policy.rs"]
mod policy;
use policy_api::*;
fn context() -> Context {
    Context { approved: true, amount: 1, daily_limit: 10, spent: 9, spent_day: 0, now: 0 }
}
#[test]
fn approval_required() {
    let mut c = context();
    c.approved = false;
    assert_eq!(policy::execute(&c), Err(PolicyError::NotApproved));
    c.approved = true;
    assert_eq!(policy::execute(&c), Ok(10));
}
#[test]
fn limits_boundary_and_denial() {
    let mut c = context();
    assert_eq!(policy::execute(&c), Ok(10));
    c.amount = 2;
    assert_eq!(policy::execute(&c), Err(PolicyError::DailyLimitExceeded));
    c.amount = 0;
    assert_eq!(policy::execute(&c), Err(PolicyError::ZeroAmount));
    c.amount = 1;
    c.daily_limit = MAX_DAILY_LIMIT + 1;
    assert_eq!(policy::execute(&c), Err(PolicyError::ParameterOutOfBounds));
}
#[test]
fn limits_day_rollover_and_clock() {
    let mut c = context();
    c.now = DAY_SECONDS;
    assert_eq!(policy::execute(&c), Ok(1));
    c.spent_day = 2;
    assert_eq!(policy::execute(&c), Err(PolicyError::ClockWentBackwards));
}
#[test]
fn limits_overflow_denied() {
    let mut c = context();
    c.spent = u64::MAX;
    assert_eq!(policy::execute(&c), Err(PolicyError::Overflow));
}
