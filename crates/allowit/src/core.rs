// Shared types and rules, included once per backend. `Address`, `String` and `Vec` come from the
// including module. Field types keep those names so Soroban contract specs name native types.

/// UTC day length in seconds.
pub const DAY: u64 = 86_400;

/// Canonical rule names. Each rule reads only its same-named Grant field.
pub const RULES: [&str; 8] = [
    "transaction_cap",
    "spent_cap",
    "day_spent_cap",
    "day_total_cap",
    "call_cap",
    "recipients",
    "tokens",
    "expiry",
];

pub use types::*;

/// Contract types. Kept apart from `Result` so generated code sees the standard prelude.
mod types {
    use super::{Address, String, Vec};

    value! {
        /// Owner-signed typed rule parameters. `None` is unset: its rule denies with `MissingGrant`.
        /// Amounts use underlying native units.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct Grant {
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
            /// Exclusive Unix timestamp after which the grant denies.
            pub expiry: Option<u64>,
        }
    }

    value! {
        /// Protected accounting proposed after this operation. Values include it once.
        /// Missing price facts set unpriced liabilities instead of spent amounts.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct AccountingHistory {
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
        /// Authenticated request facts read by rules.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct Request {
            /// Kernel-selected canonical operation name, such as `stellar::sep41_transfer`.
            pub operation: String,
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
        /// Complete rule input, computed and supplied by the wallet or server.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitEnv {
            pub grant: Grant,
            pub state: AccountingHistory,
            pub request: Request,
        }
    }

    error! {
        /// Rule denial or invalid input.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u32)]
        pub enum Error {
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
            /// Negative cap, nonpositive amount or unknown rule name.
            InvalidParameter = 11,
            /// Accounting is negative or belongs to another day.
            InvalidState = 12,
        }
    }

    /// Rule-facing name of the protected accounting.
    pub type State = AccountingHistory;
}

/// A rule's passing constraint, or its denial.
pub type Result<T = ()> = core::result::Result<T, Error>;

/// Names used by authored policy.
pub mod prelude {
    pub use super::{Address, AllowitEnv, Error, Grant, Request, Result, State};
}

/// Common preconditions of the accounting caps.
fn accounting(ctx: &AllowitEnv, cap: i128, unpriced: bool) -> Result {
    let s = &ctx.state;
    if ctx.request.amount <= 0 || cap < 0 {
        return Err(Error::InvalidParameter);
    }
    if s.day != ctx.request.now / DAY || s.spent < 0 || s.day_spent < 0 || s.day_total < 0 {
        return Err(Error::InvalidState);
    }
    if unpriced {
        return Err(Error::Unpriced);
    }
    Ok(())
}

/// Remaining headroom of a nonnegative cap.
fn left(cap: i128, used: i128, exceeded: Error) -> Result<i128> {
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
pub fn transaction_cap(ctx: &AllowitEnv, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(Error::MissingGrant)?;
    if cap < 0 || ctx.request.amount <= 0 {
        return Err(Error::InvalidParameter);
    }
    left(cap, ctx.request.amount, Error::TransactionCapExceeded)
}

/// Bound cumulative irreversible expenses, including this operation.
///
/// Returns `cap - state.spent`. Lifetime unpriced history is `Unpriced`.
/// Accounting from another day is `InvalidState`.
pub fn spent_cap(ctx: &AllowitEnv, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(Error::MissingGrant)?;
    accounting(ctx, cap, ctx.state.unpriced)?;
    left(cap, ctx.state.spent, Error::SpentCapExceeded)
}

/// Bound irreversible expenses on the request's UTC day, including this operation.
///
/// Returns `cap - state.day_spent`. Unpriced history for that day is `Unpriced`.
/// `state.day` must equal `request.now / DAY`.
pub fn day_spent_cap(ctx: &AllowitEnv, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(Error::MissingGrant)?;
    accounting(ctx, cap, ctx.state.day_unpriced)?;
    left(cap, ctx.state.day_spent, Error::DaySpentCapExceeded)
}

/// Bound gross amounts plus separate attributable gas on the request's UTC day.
/// Embedded deposit conversion fees belong to principal and count once.
///
/// Returns `cap - state.day_total`. Unpriced history for that day is `Unpriced`.
/// `state.day` must equal `request.now / DAY`.
pub fn day_total_cap(ctx: &AllowitEnv, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(Error::MissingGrant)?;
    accounting(ctx, cap, ctx.state.day_unpriced)?;
    left(cap, ctx.state.day_total, Error::DayTotalCapExceeded)
}

/// Bound successful operations, including this one and those made while this rule was skipped.
///
/// Returns `cap - state.calls`. A zero cap always denies.
pub fn call_cap(ctx: &AllowitEnv, cap: &Option<u64>) -> Result<u64> {
    let cap = cap.ok_or(Error::MissingGrant)?;
    let calls = ctx.state.calls;
    if cap == 0 || calls > cap {
        return Err(Error::CallCapExceeded);
    }
    Ok(cap - calls)
}

/// Require an exact permitted destination. Deposits name their vault as the recipient.
///
/// Returns the matched `request.recipient`. An empty list denies.
pub fn recipients(ctx: &AllowitEnv, allowed: &Option<Vec<Address>>) -> Result<Address> {
    let allowed = allowed.as_ref().ok_or(Error::MissingGrant)?;
    let recipient = &ctx.request.recipient;
    if allowed.contains(recipient) {
        Ok(recipient.clone())
    } else {
        Err(Error::RecipientNotAllowed)
    }
}

/// Require an exact permitted underlying asset contract.
///
/// Returns the matched `request.asset`. An empty list denies.
pub fn tokens(ctx: &AllowitEnv, allowed: &Option<Vec<Address>>) -> Result<Address> {
    let allowed = allowed.as_ref().ok_or(Error::MissingGrant)?;
    let asset = &ctx.request.asset;
    if allowed.contains(asset) {
        Ok(asset.clone())
    } else {
        Err(Error::TokenNotAllowed)
    }
}

/// Require an unexpired grant and request, with the request expiring no later than the grant.
///
/// Returns seconds left until `min(expiry, request.expires_at)`.
pub fn expiry(ctx: &AllowitEnv, expiry: &Option<u64>) -> Result<u64> {
    let expiry = expiry.ok_or(Error::MissingGrant)?;
    let r = &ctx.request;
    if r.now < expiry && r.now < r.expires_at && r.expires_at <= expiry {
        Ok(r.expires_at.min(expiry) - r.now)
    } else {
        Err(Error::Expired)
    }
}

/// Standard-contract preflight of one canonical prefix call `allowit::<rule>(ctx, &ctx.grant.<rule>)?;`.
/// Only this runner skips a rule whose Grant field is unset. It discards pass values.
/// Unknown names are `InvalidParameter`.
pub fn preflight(ctx: &AllowitEnv, rule: &str) -> Result {
    let grant = &ctx.grant;
    match rule {
        "transaction_cap" => {
            if grant.transaction_cap.is_some() {
                transaction_cap(ctx, &grant.transaction_cap)?;
            }
        }
        "spent_cap" => {
            if grant.spent_cap.is_some() {
                spent_cap(ctx, &grant.spent_cap)?;
            }
        }
        "day_spent_cap" => {
            if grant.day_spent_cap.is_some() {
                day_spent_cap(ctx, &grant.day_spent_cap)?;
            }
        }
        "day_total_cap" => {
            if grant.day_total_cap.is_some() {
                day_total_cap(ctx, &grant.day_total_cap)?;
            }
        }
        "call_cap" => {
            if grant.call_cap.is_some() {
                call_cap(ctx, &grant.call_cap)?;
            }
        }
        "recipients" => {
            if grant.recipients.is_some() {
                recipients(ctx, &grant.recipients)?;
            }
        }
        "tokens" => {
            if grant.tokens.is_some() {
                tokens(ctx, &grant.tokens)?;
            }
        }
        "expiry" => {
            if grant.expiry.is_some() {
                expiry(ctx, &grant.expiry)?;
            }
        }
        _ => return Err(Error::InvalidParameter),
    }
    Ok(())
}

impl Grant {
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
            Err(Error::InvalidParameter)
        } else {
            Ok(())
        }
    }
}
