use crate::{
    policy,
    policy_api::{Context, PolicyError},
};
fn ctx() -> Context {
    Context {
        approved: true,
        amount: 10,
        daily_limit: 25,
        spent: 15,
        spent_day: 1,
        now: 86_401,
    }
}
#[test]
fn exact_limit_is_allowed() {
    assert_eq!(policy::evaluate(&ctx()), Ok(25));
}
#[test]
fn over_limit_is_denied() {
    let mut c = ctx();
    c.amount = 11;
    assert_eq!(policy::evaluate(&c), Err(PolicyError::DailyLimitExceeded));
}
#[test]
fn next_day_resets_only_the_day_counter() {
    let mut c = ctx();
    c.now = 172_800;
    assert_eq!(policy::evaluate(&c), Ok(10));
}
#[test]
fn tuning_preserves_spend() {
    let mut c = ctx();
    c.daily_limit = 20;
    assert_eq!(policy::evaluate(&c), Err(PolicyError::DailyLimitExceeded));
    c.daily_limit = 30;
    assert_eq!(policy::evaluate(&c), Ok(25));
}
#[test]
fn zero_limit_pauses_transfers() {
    let mut c = ctx();
    c.daily_limit = 0;
    assert_eq!(policy::evaluate(&c), Err(PolicyError::DailyLimitExceeded));
}
#[test]
fn rejected_cases() {
    let mut c = ctx();
    c.approved = false;
    assert_eq!(policy::evaluate(&c), Err(PolicyError::NotApproved));
    c = ctx();
    c.amount = 0;
    assert_eq!(policy::evaluate(&c), Err(PolicyError::ZeroAmount));
    c = ctx();
    c.spent_day = 2;
    assert_eq!(policy::evaluate(&c), Err(PolicyError::ClockWentBackwards));
    c = ctx();
    c.spent = u64::MAX;
    assert_eq!(policy::evaluate(&c), Err(PolicyError::Overflow));
}
#[test]
fn only_declared_bounds_are_accepted() {
    assert_eq!(policy::validate_daily_limit(50_000_000), Ok(()));
    assert_eq!(
        policy::validate_daily_limit(50_000_001),
        Err(PolicyError::ParameterOutOfBounds)
    );
}
