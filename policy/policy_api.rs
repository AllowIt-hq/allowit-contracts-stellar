#[cfg_attr(feature = "stellar", soroban_sdk::contracttype)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub approved: bool,
    pub amount: u64,
    pub daily_limit: u64,
    pub spent: u64,
    pub spent_day: u64,
    pub now: u64,
}

#[cfg_attr(feature = "stellar", soroban_sdk::contracterror)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PolicyError {
    NotApproved = 1,
    ZeroAmount = 2,
    ParameterOutOfBounds = 3,
    ClockWentBackwards = 4,
    Overflow = 5,
    DailyLimitExceeded = 6,
}

/// Standard AllowIt system functions. Shared verbatim across native runtimes.
pub const MAX_DAILY_LIMIT: u64 = 50_000_000;
pub const DAY_SECONDS: u64 = 86_400;

pub fn validate_daily_limit(value: u64) -> Result<(), PolicyError> {
    if value > MAX_DAILY_LIMIT {
        return Err(PolicyError::ParameterOutOfBounds);
    }
    Ok(())
}

pub fn require_approval(ctx: &Context) -> Result<(), PolicyError> {
    if !ctx.approved {
        return Err(PolicyError::NotApproved);
    }
    Ok(())
}

/// Returns the next daily spend; the custody runtime commits it atomically with transfer.
pub fn enforce_daily_limit(ctx: &Context) -> Result<u64, PolicyError> {
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
