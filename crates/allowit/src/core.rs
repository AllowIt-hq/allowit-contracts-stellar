// Shared types and rules, included once per backend. `Address` and `Vec` come from the
// including module. Field types keep those names so Soroban contract specs name native types.

/// UTC day length in seconds.
pub const DAY: u64 = 86_400;

pub use types::*;

/// Contract types. Kept apart from `Result` so generated code sees the standard prelude.
/// `AllowitRule` variants keep the snake-case names of their functions and Grant fields.
#[allow(non_camel_case_types)]
mod types {
    use super::{Address, Vec};

    value! {
        /// Owner-signed typed rule parameters. `None` is unset: its rule denies with `MissingGrant`.
        /// Amounts use underlying native units.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct AllowitGrant {
            /// Nonnegative gross ceiling for one operation.
            pub transaction_cap: Option<i128>,
            /// Nonnegative cumulative irreversible-expense ceiling.
            pub spent_cap: Option<i128>,
            /// Nonnegative UTC-day irreversible-expense ceiling.
            pub day_spent_cap: Option<i128>,
            /// Nonnegative UTC-day gross amount plus separate attributable gas ceiling.
            pub day_total_cap: Option<i128>,
            /// Successful operation count ceiling. Zero denies every operation.
            pub call_cap: Option<u64>,
            /// Exact permitted destinations, including deposit vaults. Empty denies.
            pub recipients: Option<Vec<Address>>,
            /// Exact permitted underlying asset contracts. Empty denies.
            pub tokens: Option<Vec<Address>>,
            /// Exclusive Unix timestamp; the grant denies at and after it.
            pub expiry: Option<u64>,
        }
    }

    value! {
        /// Protected accounting proposed after this operation. Values include it once.
        /// Missing price facts set unpriced liabilities instead of spent amounts.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct AllowitAccountingHistory {
            /// Successful operations, including this one.
            pub calls: u64,
            /// Lifetime irreversible expenses.
            pub spent: i128,
            /// A lifetime operation lacked price facts.
            pub unpriced: bool,
            /// UTC day of the daily values (Unix seconds / 86400).
            pub day: u64,
            /// Irreversible expenses on `day`.
            pub day_spent: i128,
            /// Gross amounts plus separate attributable gas on `day`.
            pub day_total: i128,
            /// An operation on `day` lacked price facts.
            pub day_unpriced: bool,
        }
    }

    value! {
        /// Kernel-selected native operation. Variants keep the canonical `stellar::<name>` names.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum AllowitOperation {
            sep41_transfer,
            sep56_deposit,
        }
    }

    value! {
        /// Authenticated request facts read by rules.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitRequest {
            /// Kernel-selected native operation.
            pub operation: AllowitOperation,
            /// Immutable underlying asset contract.
            pub asset: Address,
            /// Exact destination: the payment recipient or the deposit vault.
            pub recipient: Address,
            /// Positive gross underlying debit.
            pub amount: i128,
            /// Authenticated ledger close time in Unix seconds.
            pub now: u64,
            /// Exclusive request expiry in Unix seconds.
            pub expires_at: u64,
        }
    }

    value! {
        /// Canonical rule. Each variant names its rule function and its same-named Grant field.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum AllowitRule {
            transaction_cap,
            spent_cap,
            day_spent_cap,
            day_total_cap,
            call_cap,
            recipients,
            tokens,
            expiry,
        }
    }

    value! {
        /// Complete rule input, computed and supplied by the wallet or server.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitContext {
            pub grant: AllowitGrant,
            pub state: AllowitAccountingHistory,
            pub request: AllowitRequest,
        }
    }

    error! {
        /// Rule denial or invalid input.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u32)]
        pub enum AllowitError {
            /// The rule's Grant field is unset.
            MissingGrant = 1,
            TransactionCapExceeded = 2,
            SpentCapExceeded = 3,
            DaySpentCapExceeded = 4,
            DayTotalCapExceeded = 5,
            CallCapExceeded = 6,
            RecipientNotAllowed = 7,
            TokenNotAllowed = 8,
            Expired = 9,
            /// Selected expense accounting has an unpriced liability.
            Unpriced = 10,
            /// Negative cap or nonpositive transaction amount.
            InvalidParameter = 11,
            /// Read accounting is negative or belongs to another day.
            InvalidState = 12,
        }
    }
}

/// A rule's passing constraint, or its denial.
pub type Result<T = ()> = core::result::Result<T, AllowitError>;

/// Names used by authored policy.
pub mod prelude {
    pub use super::{
        AllowitAccountingHistory, Address, AllowitContext, AllowitError, AllowitGrant, AllowitOperation, AllowitRequest, Result,
    };
}

/// Check one accounting cap against only the facts it reads. `current` is false for daily
/// values of another UTC day.
fn accounting(cap: i128, used: i128, unpriced: bool, current: bool, exceeded: AllowitError) -> Result<i128> {
    if cap < 0 {
        return Err(AllowitError::InvalidParameter);
    }
    if used < 0 || !current {
        return Err(AllowitError::InvalidState);
    }
    if unpriced {
        return Err(AllowitError::Unpriced);
    }
    left(cap, used, exceeded)
}

/// Daily values belong to the request's UTC day.
fn today(ctx: &AllowitContext) -> bool {
    ctx.state.day == ctx.request.now / DAY
}

/// Remaining headroom of a nonnegative cap.
fn left(cap: i128, used: i128, exceeded: AllowitError) -> Result<i128> {
    if used > cap {
        Err(exceeded)
    } else {
        Ok(cap - used)
    }
}

/// Bound the gross amount of one operation.
///
/// Returns `cap - request.amount`, the headroom left for this operation.
/// A negative cap or nonpositive amount is `InvalidParameter`.
pub fn transaction_cap(ctx: &AllowitContext, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    if cap < 0 || ctx.request.amount <= 0 {
        return Err(AllowitError::InvalidParameter);
    }
    left(cap, ctx.request.amount, AllowitError::TransactionCapExceeded)
}

/// Bound cumulative irreversible expenses, including this operation.
///
/// Returns `cap - state.spent`. Lifetime unpriced history is `Unpriced`.
pub fn spent_cap(ctx: &AllowitContext, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    let s = &ctx.state;
    accounting(cap, s.spent, s.unpriced, true, AllowitError::SpentCapExceeded)
}

/// Bound irreversible expenses on the request's UTC day, including this operation.
///
/// Returns `cap - state.day_spent`. Unpriced history for that day is `Unpriced`.
/// `state.day` must equal `request.now / DAY`.
pub fn day_spent_cap(ctx: &AllowitContext, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    let s = &ctx.state;
    let e = AllowitError::DaySpentCapExceeded;
    accounting(cap, s.day_spent, s.day_unpriced, today(ctx), e)
}

/// Bound gross amounts plus separate attributable gas on the request's UTC day.
/// Embedded deposit conversion fees belong to principal and count once.
///
/// Returns `cap - state.day_total`. Unpriced history for that day is `Unpriced`.
/// `state.day` must equal `request.now / DAY`.
pub fn day_total_cap(ctx: &AllowitContext, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    let s = &ctx.state;
    let e = AllowitError::DayTotalCapExceeded;
    accounting(cap, s.day_total, s.day_unpriced, today(ctx), e)
}

/// Bound successful operations, including this one and those made while this rule was skipped.
///
/// Returns `cap - state.calls`. A zero cap always denies.
pub fn call_cap(ctx: &AllowitContext, cap: &Option<u64>) -> Result<u64> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    let calls = ctx.state.calls;
    if cap == 0 || calls > cap {
        return Err(AllowitError::CallCapExceeded);
    }
    Ok(cap - calls)
}

/// Require an exact permitted destination. Deposits name their vault as the recipient.
///
/// Returns the matched `request.recipient`. An empty list denies.
pub fn recipients(ctx: &AllowitContext, allowed: &Option<Vec<Address>>) -> Result<Address> {
    let allowed = allowed.as_ref().ok_or(AllowitError::MissingGrant)?;
    let recipient = &ctx.request.recipient;
    if allowed.contains(recipient) {
        Ok(recipient.clone())
    } else {
        Err(AllowitError::RecipientNotAllowed)
    }
}

/// Require an exact permitted underlying asset contract.
///
/// Returns the matched `request.asset`. An empty list denies.
pub fn tokens(ctx: &AllowitContext, allowed: &Option<Vec<Address>>) -> Result<Address> {
    let allowed = allowed.as_ref().ok_or(AllowitError::MissingGrant)?;
    let asset = &ctx.request.asset;
    if allowed.contains(asset) {
        Ok(asset.clone())
    } else {
        Err(AllowitError::TokenNotAllowed)
    }
}

/// Require an unexpired grant and request, with the request expiring no later than the grant.
///
/// Returns `expiry - request.now`, the seconds the grant has left.
pub fn expiry(ctx: &AllowitContext, expiry: &Option<u64>) -> Result<u64> {
    let expiry = expiry.ok_or(AllowitError::MissingGrant)?;
    let r = &ctx.request;
    if r.now < expiry && r.now < r.expires_at && r.expires_at <= expiry {
        Ok(expiry - r.now)
    } else {
        Err(AllowitError::Expired)
    }
}

/// Standard-contract preflight of one canonical prefix call `allowit::<rule>(ctx, &ctx.grant.<rule>)?;`.
/// Only this runner skips a rule whose Grant field is unset. It discards pass values.
pub fn preflight(ctx: &AllowitContext, rule: AllowitRule) -> Result {
    let grant = &ctx.grant;
    match rule {
        AllowitRule::transaction_cap => {
            if grant.transaction_cap.is_some() {
                transaction_cap(ctx, &grant.transaction_cap)?;
            }
        }
        AllowitRule::spent_cap => {
            if grant.spent_cap.is_some() {
                spent_cap(ctx, &grant.spent_cap)?;
            }
        }
        AllowitRule::day_spent_cap => {
            if grant.day_spent_cap.is_some() {
                day_spent_cap(ctx, &grant.day_spent_cap)?;
            }
        }
        AllowitRule::day_total_cap => {
            if grant.day_total_cap.is_some() {
                day_total_cap(ctx, &grant.day_total_cap)?;
            }
        }
        AllowitRule::call_cap => {
            if grant.call_cap.is_some() {
                call_cap(ctx, &grant.call_cap)?;
            }
        }
        AllowitRule::recipients => {
            if grant.recipients.is_some() {
                recipients(ctx, &grant.recipients)?;
            }
        }
        AllowitRule::tokens => {
            if grant.tokens.is_some() {
                tokens(ctx, &grant.tokens)?;
            }
        }
        AllowitRule::expiry => {
            if grant.expiry.is_some() {
                expiry(ctx, &grant.expiry)?;
            }
        }
    }
    Ok(())
}

impl AllowitGrant {
    /// Check owner configuration before storing it. Negative caps are `InvalidParameter`.
    /// The struct enforces types. Unset fields are valid configuration.
    pub fn validate(&self) -> Result {
        let caps = [
            self.transaction_cap,
            self.spent_cap,
            self.day_spent_cap,
            self.day_total_cap,
        ];
        if caps.iter().flatten().any(|cap| *cap < 0) {
            Err(AllowitError::InvalidParameter)
        } else {
            Ok(())
        }
    }
}
