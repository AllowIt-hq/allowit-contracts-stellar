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
