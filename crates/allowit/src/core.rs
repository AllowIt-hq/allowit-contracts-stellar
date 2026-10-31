// Shared types and rules, included once per backend. The including module supplies `Address`,
// `AllowitEnv`, `AllowitStateMap`, `AllowitValue` and `Vec`, and the state primitives `read`,
// `write`, `record`, `take_writes` and `merge`. Field types keep those names so Soroban contract
// specs name native types.

/// UTC day length in seconds.
pub const DAY: u64 = 86_400;

pub use types::*;

/// Contract types. Kept apart from `Result` so generated code sees the standard prelude.
/// `AllowitRule` variants keep the snake-case names of their functions and Grant fields.
#[allow(non_camel_case_types)]
mod types {
    use super::{Address, AllowitEnv, AllowitStateMap, Vec};

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
            /// Irreversible expense of this operation from the validated expense bounds; zero when unpriced.
            pub spent_units: i128,
            /// Attributable gas of this operation from the validated expense bounds; zero when unpriced.
            pub gas_units: i128,
            /// The request carries no expense bounds.
            pub unpriced: bool,
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

    /// Complete rule input, supplied by the wallet or server. Plain data: `env` is the backend
    /// environment, a Soroban `Env` onchain and an `AllowitEnv` on the host; `state` is the current
    /// policy state, before this operation.
    #[derive(Clone)]
    pub struct AllowitContext {
        pub env: AllowitEnv,
        pub grant: AllowitGrant,
        pub state: AllowitStateMap,
        pub request: AllowitRequest,
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
            /// Negative cap, nonpositive amount, negative request units or invalid state key.
            InvalidParameter = 11,
            /// Read state is negative, of another type, or belongs to a later day.
            InvalidState = 12,
            /// An accounting sum leaves its integer range.
            Overflow = 13,
            /// A server-only function this evaluator does not provide.
            Unsupported = 14,
        }
    }
}

/// A rule's passing constraint, or its denial.
pub type Result<T = ()> = core::result::Result<T, AllowitError>;

/// Names used by authored policy.
pub mod prelude {
    pub use super::{
        Address, AllowitContext, AllowitError, AllowitGrant, AllowitOperation, AllowitRequest,
        Result,
    };
}

/// Standard state keys. `post_flight` writes them; policy writes apply after them.
pub const SPENT: &str = "spent";
pub const DAY_SPENT: &str = "day_spent";
pub const DAY_TOTAL: &str = "day_total";
pub const CALLS: &str = "calls";
pub const DAY_KEY: &str = "day";
pub const UNPRICED: &str = "unpriced";
pub const DAY_UNPRICED: &str = "day_unpriced";

/// Standard values of a state map. An absent key reads as zero or false.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllowitStandardState {
    /// Successful operations.
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

impl AllowitStandardState {
    /// Decode the standard keys of `state`. A value of another type is `InvalidState`.
    pub fn read(env: &AllowitEnv, state: &AllowitStateMap) -> Result<Self> {
        Ok(Self {
            calls: read(env, state, CALLS)?.unwrap_or_default(),
            spent: read(env, state, SPENT)?.unwrap_or_default(),
            unpriced: read(env, state, UNPRICED)?.unwrap_or_default(),
            day: read(env, state, DAY_KEY)?.unwrap_or_default(),
            day_spent: read(env, state, DAY_SPENT)?.unwrap_or_default(),
            day_total: read(env, state, DAY_TOTAL)?.unwrap_or_default(),
            day_unpriced: read(env, state, DAY_UNPRICED)?.unwrap_or_default(),
        })
    }

    /// Write every standard key into `state`.
    pub fn write(&self, env: &AllowitEnv, state: &mut AllowitStateMap) -> Result {
        write(env, state, CALLS, self.calls)?;
        write(env, state, SPENT, self.spent)?;
        write(env, state, UNPRICED, self.unpriced)?;
        write(env, state, DAY_KEY, self.day)?;
        write(env, state, DAY_SPENT, self.day_spent)?;
        write(env, state, DAY_TOTAL, self.day_total)?;
        write(env, state, DAY_UNPRICED, self.day_unpriced)
    }
}

/// A state key is 1 to 32 ASCII letters, digits or underscores, as a Soroban `Symbol` requires.
fn key_ok(key: &str) -> bool {
    (1..=32).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Checked sum of accounting values.
fn sum(a: i128, b: i128) -> Result<i128> {
    a.checked_add(b).ok_or(AllowitError::Overflow)
}

/// The request's own contribution: the sum of nonnegative request units.
fn contribution(parts: &[i128]) -> Result<i128> {
    parts.iter().try_fold(0, |total, part| {
        if *part < 0 {
            Err(AllowitError::InvalidParameter)
        } else {
            sum(total, *part)
        }
    })
}

/// Standard values of the current state.
fn standard(ctx: &AllowitContext) -> Result<AllowitStandardState> {
    AllowitStandardState::read(&ctx.env, &ctx.state)
}

/// Daily values `(day_spent, day_total, day_unpriced)` on the request's UTC day: those of an
/// earlier day roll over to zero, and a later day is `InvalidState`.
fn daily(ctx: &AllowitContext, s: &AllowitStandardState) -> Result<(i128, i128, bool)> {
    let today = ctx.request.now / DAY;
    if s.day > today {
        Err(AllowitError::InvalidState)
    } else if s.day < today {
        Ok((0, 0, false))
    } else {
        Ok((s.day_spent, s.day_total, s.day_unpriced))
    }
}

/// Check one accounting cap: `used + add <= cap`, against only the facts it reads.
fn accounting(
    cap: i128,
    used: i128,
    unpriced: bool,
    add: Result<i128>,
    exceeded: AllowitError,
) -> Result<i128> {
    if cap < 0 {
        return Err(AllowitError::InvalidParameter);
    }
    if used < 0 {
        return Err(AllowitError::InvalidState);
    }
    if unpriced {
        return Err(AllowitError::Unpriced);
    }
    left(cap, sum(used, add?)?, exceeded)
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
/// Returns `cap - request.amount`. A negative cap or nonpositive amount is `InvalidParameter`.
pub fn transaction_cap(ctx: &AllowitContext, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    if cap < 0 || ctx.request.amount <= 0 {
        return Err(AllowitError::InvalidParameter);
    }
    left(
        cap,
        ctx.request.amount,
        AllowitError::TransactionCapExceeded,
    )
}

/// Bound cumulative irreversible expenses: `spent + request.spent_units <= cap`.
///
/// Returns the headroom left after this operation. Lifetime or request unpriced is `Unpriced`.
pub fn spent_cap(ctx: &AllowitContext, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    let (s, r) = (standard(ctx)?, &ctx.request);
    let add = contribution(&[r.spent_units]);
    let e = AllowitError::SpentCapExceeded;
    accounting(cap, s.spent, s.unpriced || r.unpriced, add, e)
}

/// Bound irreversible expenses on the request's UTC day: `day_spent + request.spent_units <= cap`.
/// `day_spent` is zero when the state belongs to an earlier day.
///
/// Returns the headroom left after this operation. Unpriced today or in the request is `Unpriced`.
pub fn day_spent_cap(ctx: &AllowitContext, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    let (day_spent, _, day_unpriced) = daily(ctx, &standard(ctx)?)?;
    let r = &ctx.request;
    let add = contribution(&[r.spent_units]);
    let e = AllowitError::DaySpentCapExceeded;
    accounting(cap, day_spent, day_unpriced || r.unpriced, add, e)
}

/// Bound gross amounts plus separate attributable gas on the request's UTC day:
/// `day_total + request.amount + request.gas_units <= cap`. Embedded deposit conversion fees
/// belong to principal and count once.
///
/// Returns the headroom left after this operation. Unpriced today or in the request is `Unpriced`.
pub fn day_total_cap(ctx: &AllowitContext, cap: &Option<i128>) -> Result<i128> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    let (_, day_total, day_unpriced) = daily(ctx, &standard(ctx)?)?;
    let r = &ctx.request;
    let add = contribution(&[r.amount, r.gas_units]);
    let e = AllowitError::DayTotalCapExceeded;
    accounting(cap, day_total, day_unpriced || r.unpriced, add, e)
}

/// Bound successful operations, including those made while this rule was skipped:
/// `calls + 1 <= cap`.
///
/// Returns the operations left after this one. A zero cap always denies.
pub fn call_cap(ctx: &AllowitContext, cap: &Option<u64>) -> Result<u64> {
    let cap = cap.ok_or(AllowitError::MissingGrant)?;
    let next = standard(ctx)?
        .calls
        .checked_add(1)
        .ok_or(AllowitError::Overflow)?;
    if next > cap {
        return Err(AllowitError::CallCapExceeded);
    }
    Ok(cap - next)
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

/// The current value of a state key, before this operation, or `None`. Writes of this run apply
/// only in `post_flight`. A value of another type is `InvalidState`.
pub fn get_state<V: AllowitValue>(ctx: &AllowitContext, key: &str) -> Result<Option<V>> {
    read(&ctx.env, &ctx.state, key)
}

/// Record a policy write of `key`. `post_flight` applies it after the standard update, so it may
/// replace a standard key. A key is 1 to 32 ASCII letters, digits or underscores.
pub fn set_state<V: AllowitValue>(ctx: &AllowitContext, key: &str, value: V) -> Result {
    record(&ctx.env, key, value)
}

/// Standard-contract preflight of one canonical prefix call `allowit::<rule>(ctx, &ctx.grant.<rule>)?;`.
/// Only this runner skips a rule whose Grant field is unset. It discards pass values.
pub fn preflight(ctx: &AllowitContext, rule: AllowitRule) -> Result {
    let g = &ctx.grant;
    match rule {
        AllowitRule::transaction_cap if g.transaction_cap.is_some() => {
            transaction_cap(ctx, &g.transaction_cap)?;
        }
        AllowitRule::spent_cap if g.spent_cap.is_some() => {
            spent_cap(ctx, &g.spent_cap)?;
        }
        AllowitRule::day_spent_cap if g.day_spent_cap.is_some() => {
            day_spent_cap(ctx, &g.day_spent_cap)?;
        }
        AllowitRule::day_total_cap if g.day_total_cap.is_some() => {
            day_total_cap(ctx, &g.day_total_cap)?;
        }
        AllowitRule::call_cap if g.call_cap.is_some() => {
            call_cap(ctx, &g.call_cap)?;
        }
        AllowitRule::recipients if g.recipients.is_some() => {
            recipients(ctx, &g.recipients)?;
        }
        AllowitRule::tokens if g.tokens.is_some() => {
            tokens(ctx, &g.tokens)?;
        }
        AllowitRule::expiry if g.expiry.is_some() => {
            expiry(ctx, &g.expiry)?;
        }
        _ => {}
    }
    Ok(())
}

/// Standard values of `state` and its daily values on the request's day. A value of another type,
/// a negative amount or a later day is `InvalidState`.
fn decode(
    ctx: &AllowitContext,
    state: &AllowitStateMap,
) -> Result<(AllowitStandardState, (i128, i128, bool))> {
    let s = AllowitStandardState::read(&ctx.env, state)?;
    let d = daily(ctx, &s)?;
    if s.spent < 0 || d.0 < 0 || d.1 < 0 {
        return Err(AllowitError::InvalidState);
    }
    Ok((s, d))
}

/// State after an approved operation, computed by the wallet and the server alike: roll the UTC
/// day over, count the call, add spent and gross amounts, mark an unpriced request, then apply the
/// policy's buffered writes. It clears the write buffer first, even when it fails. A result that
/// later operations could not decode, or whose totals leave no room for one more call or unit, is
/// `InvalidState`, so a policy write cannot make every later standard update fail.
pub fn post_flight(ctx: &AllowitContext) -> Result<AllowitStateMap> {
    let writes = take_writes(&ctx.env);
    let (mut s, (day_spent, day_total, day_unpriced)) = decode(ctx, &ctx.state)?;
    let r = &ctx.request;
    s.calls = s.calls.checked_add(1).ok_or(AllowitError::Overflow)?;
    s.day = r.now / DAY;
    s.spent = sum(s.spent, contribution(&[r.spent_units])?)?;
    s.day_spent = sum(day_spent, contribution(&[r.spent_units])?)?;
    s.day_total = sum(day_total, contribution(&[r.amount, r.gas_units])?)?;
    s.unpriced |= r.unpriced;
    s.day_unpriced = day_unpriced || r.unpriced;
    let mut state = ctx.state.clone();
    s.write(&ctx.env, &mut state)?;
    merge(&mut state, writes);
    // The next standard update adds one call and may add a unit to each total.
    let (s, (day_spent, day_total, _)) = decode(ctx, &state)?;
    if s.calls == u64::MAX || [s.spent, day_spent, day_total].contains(&i128::MAX) {
        return Err(AllowitError::InvalidState);
    }
    Ok(state)
}

/// One policy evaluation, the server's entry point: clear stale writes, run `execute`, then
/// `post_flight` on approval. A denial discards the policy's writes, so no write outlives it.
pub fn evaluate(
    ctx: &AllowitContext,
    execute: impl FnOnce(&AllowitContext) -> Result,
) -> Result<AllowitStateMap> {
    take_writes(&ctx.env);
    let run = execute(ctx);
    if run.is_err() {
        take_writes(&ctx.env);
    }
    run.and_then(|()| post_flight(ctx))
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
