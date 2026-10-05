//! Native policy source, copied byte-for-byte into both chain builds.
//! Amounts use six-decimal policy units. Only daily_limit is explicitly tunable.
use crate::policy_api::{Context, PolicyError};

pub const MAX_DAILY_LIMIT: u64 = 50_000_000;
pub const DAY_SECONDS: u64 = 86_400;

pub fn validate_daily_limit(value: u64) -> Result<(), PolicyError> {
    if value > MAX_DAILY_LIMIT {
        return Err(PolicyError::ParameterOutOfBounds);
    }
    Ok(())
}

pub fn evaluate(ctx: &Context) -> Result<u64, PolicyError> {
    if !ctx.approved {
        return Err(PolicyError::NotApproved);
    }
    if ctx.amount == 0 {
        return Err(PolicyError::ZeroAmount);
    }
    validate_daily_limit(ctx.daily_limit)?;
    let day = ctx.now / DAY_SECONDS;
    if day < ctx.spent_day {
        return Err(PolicyError::ClockWentBackwards);
    }
    let spent = if day == ctx.spent_day { ctx.spent } else { 0 };
    let next = spent.checked_add(ctx.amount).ok_or(PolicyError::Overflow)?;
    if next > ctx.daily_limit {
        return Err(PolicyError::DailyLimitExceeded);
    }
    Ok(next)
}
