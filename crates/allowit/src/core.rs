// Shared types and rules, included once per backend. The including module supplies `Address`,
// `AllowitEnv`, `Map`, `String`, `Symbol` and `Vec`, and the map primitives `lookup`, `insert`,
// `count`, `text_len`, `each_value`, `each_item`, `record`, `take_writes` and `merge`. Field
// types keep those names so Soroban contract specs name native types.

/// UTC day length in seconds.
pub const DAY: u64 = 86_400;

pub use types::*;

/// Contract types. Kept apart from `Result` so generated code sees the standard prelude.
/// `AllowitRule` variants keep the snake-case names of their functions and param keys.
#[allow(non_camel_case_types)]
mod types {
    use super::{Address, AllowitEnv, AllowitMap, Map, String, Symbol, Vec};

    value! {
        /// One value of params, request args and policy state.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub enum AllowitValue {
            /// Signed integer: amounts, counts, days and timestamps.
            Int(i128),
            /// Flag.
            Bool(bool),
            /// Text of at most `MAX_TEXT` bytes.
            Str(String),
            /// Exact Stellar account or contract.
            Addr(Address),
            /// Ordered values, such as the addresses of an allowlist.
            List(Vec<AllowitValue>),
        }
    }

    value! {
        /// Key => value params: the owner's constructor params in `ctx.params` and the agent's
        /// execution params in `ctx.request.args`. An absent key is unset.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct AllowitParams(
            /// The key => value map. Policy reads it only through `get`.
            pub Map<Symbol, AllowitValue>,
        );
    }

    value! {
        /// Kernel-selected native operation. Variants keep the canonical `stellar::<name>` names.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum AllowitOperation {
            /// SEP-41 token transfer to a recipient.
            sep41_transfer,
            /// SEP-56 deposit into a vault, which is the recipient.
            sep56_deposit,
        }
    }

    value! {
        /// Authenticated request facts read by rules, and the agent's execution params.
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
            /// The agent's execution params of this call, covered by the agent and server
            /// signatures. Never stored; canonical rules and the standard contract ignore them.
            pub args: AllowitParams,
        }
    }

    value! {
        /// Canonical rule. Each variant names its rule function and its canonical param key.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum AllowitRule {
            /// `transaction_cap`: gross ceiling of one operation.
            transaction_cap,
            /// `spent_cap`: cumulative irreversible-expense ceiling.
            spent_cap,
            /// `day_spent_cap`: UTC-day irreversible-expense ceiling.
            day_spent_cap,
            /// `day_total_cap`: UTC-day gross amount plus gas ceiling.
            day_total_cap,
            /// `call_cap`: successful operation count ceiling.
            call_cap,
            /// `recipients`: permitted destinations.
            recipients,
            /// `tokens`: permitted underlying assets.
            tokens,
            /// `expiry`: exclusive Unix timestamp of the params.
            expiry,
        }
    }

    /// Which params a wallet admits and which policy state it stores.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AllowitTier {
        /// Simple and Common: the canonical params only, and only the standard state keys,
        /// because only the canonical prefix runs onchain.
        Standard,
        /// Custom: any bounded params, and every key the compiled policy writes.
        Custom,
    }

    /// Complete rule input, supplied by the wallet or server. Plain data without methods.
    #[derive(Clone)]
    pub struct AllowitContext {
        /// Backend environment: a Soroban `Env` onchain and an `AllowitEnv` on the host.
        pub env: AllowitEnv,
        /// The owner's constructor params, set at install and changed by owner-signed update.
        pub params: AllowitParams,
        /// Current policy state, before this operation.
        pub state: AllowitMap,
        /// Authenticated request facts and the agent's execution params.
        pub request: AllowitRequest,
    }

    error! {
        /// Rule denial or invalid input.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(u32)]
        pub enum AllowitError {
            /// The rule's param is unset.
            MissingParam = 1,
            /// The amount exceeds `transaction_cap`.
            TransactionCapExceeded = 2,
            /// Lifetime expenses would exceed `spent_cap`.
            SpentCapExceeded = 3,
            /// Expenses of the UTC day would exceed `day_spent_cap`.
            DaySpentCapExceeded = 4,
            /// Gross amounts and gas of the UTC day would exceed `day_total_cap`.
            DayTotalCapExceeded = 5,
            /// This operation would exceed `call_cap`.
            CallCapExceeded = 6,
            /// The destination is not in `recipients`.
            RecipientNotAllowed = 7,
            /// The asset is not in `tokens`.
            TokenNotAllowed = 8,
            /// The params or the request have expired.
            Expired = 9,
            /// Selected expense accounting has an unpriced liability.
            Unpriced = 10,
            /// A param of the wrong type or range, a nonpositive amount, negative request units,
            /// or a key or value outside its bounds.
            InvalidParam = 11,
            /// Read state is negative, of another type, or belongs to a later day.
            InvalidState = 12,
            /// An accounting sum leaves its integer range.
            Overflow = 13,
            /// A server-only function this evaluator does not provide, or a policy write that a
            /// standard wallet cannot store.
            Unsupported = 14,
        }
    }
}

/// Key => value map of params, request args and policy state.
pub type AllowitMap = Map<Symbol, AllowitValue>;

/// A rule's passing constraint, or its denial.
pub type Result<T = ()> = core::result::Result<T, AllowitError>;

/// Names used by authored policy.
pub mod prelude {
    pub use super::{
        Address, AllowitContext, AllowitError, AllowitOperation, AllowitRequest, AllowitValue,
        Result,
    };
}

// Canonical param keys, read by the same-named rules.
/// Canonical param key of `transaction_cap`: nonnegative `Int`.
pub const TRANSACTION_CAP: &str = "transaction_cap";
/// Canonical param key of `spent_cap`: nonnegative `Int`.
pub const SPENT_CAP: &str = "spent_cap";
/// Canonical param key of `day_spent_cap`: nonnegative `Int`.
pub const DAY_SPENT_CAP: &str = "day_spent_cap";
/// Canonical param key of `day_total_cap`: nonnegative `Int`.
pub const DAY_TOTAL_CAP: &str = "day_total_cap";
/// Canonical param key of `call_cap`: `Int` in the `u64` range.
pub const CALL_CAP: &str = "call_cap";
/// Canonical param key of `recipients`: `List` of `Addr`.
pub const RECIPIENTS: &str = "recipients";
/// Canonical param key of `tokens`: `List` of `Addr`.
pub const TOKENS: &str = "tokens";
/// Canonical param key of `expiry`: `Int` in the `u64` range.
pub const EXPIRY: &str = "expiry";

// Bounds of params, args and state values.
/// Most params that a Custom wallet stores.
pub const MAX_PARAMS: u32 = 32;
/// Most execution params that one request carries.
pub const MAX_ARGS: u32 = 16;
/// Most values nested in one value, such as the addresses of an allowlist.
pub const MAX_ITEMS: u32 = 64;
/// Longest text value, in bytes.
pub const MAX_TEXT: u32 = 256;

// Standard state keys. `post_flight` writes them; Custom policy writes apply after them.
/// Standard key: lifetime irreversible expenses.
pub const SPENT: &str = "spent";
/// Standard key: irreversible expenses on `day`.
pub const DAY_SPENT: &str = "day_spent";
/// Standard key: gross amounts plus separate attributable gas on `day`.
pub const DAY_TOTAL: &str = "day_total";
/// Standard key: successful operations.
pub const CALLS: &str = "calls";
/// Standard key: UTC day of the daily values.
pub const DAY_KEY: &str = "day";
/// Standard key: a lifetime operation lacked price facts.
pub const UNPRICED: &str = "unpriced";
/// Standard key: an operation on `day` lacked price facts.
pub const DAY_UNPRICED: &str = "day_unpriced";

/// Every canonical rule, in param key order.
pub const RULES: [AllowitRule; 8] = [
    AllowitRule::transaction_cap,
    AllowitRule::spent_cap,
    AllowitRule::day_spent_cap,
    AllowitRule::day_total_cap,
    AllowitRule::call_cap,
    AllowitRule::recipients,
    AllowitRule::tokens,
    AllowitRule::expiry,
];

impl AllowitRule {
    /// The canonical param key that the standard preflight reads for this rule: its own name.
    pub fn key(self) -> &'static str {
        match self {
            AllowitRule::transaction_cap => TRANSACTION_CAP,
            AllowitRule::spent_cap => SPENT_CAP,
            AllowitRule::day_spent_cap => DAY_SPENT_CAP,
            AllowitRule::day_total_cap => DAY_TOTAL_CAP,
            AllowitRule::call_cap => CALL_CAP,
            AllowitRule::recipients => RECIPIENTS,
            AllowitRule::tokens => TOKENS,
            AllowitRule::expiry => EXPIRY,
        }
    }
}

impl AllowitParams {
    /// The value of `key`, or `None` when it is unset. A key that no map can hold, such as one
    /// with a space, is unset. Values are owned because Soroban maps decode them on read.
    pub fn get(&self, key: &str) -> Option<AllowitValue> {
        lookup(&self.0, key)
    }
}

// Typed views of a value: `From` builds one, and `TryFrom` reads one or is `InvalidParam`.
/// One `From` and `TryFrom` pair per scalar type.
macro_rules! scalars {
    ($($t:ty => $variant:ident($from:expr, $into:expr)),*) => {$(
        impl From<$t> for AllowitValue {
            /// The value holding this scalar.
            fn from(value: $t) -> Self {
                AllowitValue::$variant($from(value))
            }
        }
        impl TryFrom<AllowitValue> for $t {
            type Error = AllowitError;
            /// The scalar of a value of this type and range.
            fn try_from(value: AllowitValue) -> Result<$t> {
                match value {
                    AllowitValue::$variant(inner) => $into(inner),
                    _ => Err(AllowitError::InvalidParam),
                }
            }
        }
    )*};
}
scalars!(
    i128 => Int(core::convert::identity, Ok),
    u64 => Int(i128::from, |n| u64::try_from(n).map_err(|_| AllowitError::InvalidParam)),
    bool => Bool(core::convert::identity, Ok),
    Address => Addr(core::convert::identity, Ok)
);

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
    pub fn read(state: &AllowitMap) -> Result<Self> {
        Ok(Self {
            calls: read(state, CALLS)?.unwrap_or_default(),
            spent: read(state, SPENT)?.unwrap_or_default(),
            unpriced: read(state, UNPRICED)?.unwrap_or_default(),
            day: read(state, DAY_KEY)?.unwrap_or_default(),
            day_spent: read(state, DAY_SPENT)?.unwrap_or_default(),
            day_total: read(state, DAY_TOTAL)?.unwrap_or_default(),
            day_unpriced: read(state, DAY_UNPRICED)?.unwrap_or_default(),
        })
    }

    /// Write every standard key into `state`.
    pub fn write(&self, state: &mut AllowitMap) -> Result {
        insert(state, CALLS, self.calls.into())?;
        insert(state, SPENT, self.spent.into())?;
        insert(state, UNPRICED, self.unpriced.into())?;
        insert(state, DAY_KEY, self.day.into())?;
        insert(state, DAY_SPENT, self.day_spent.into())?;
        insert(state, DAY_TOTAL, self.day_total.into())?;
        insert(state, DAY_UNPRICED, self.day_unpriced.into())
    }
}

/// A key is 1 to 32 ASCII letters, digits or underscores, as a Soroban `Symbol` requires.
fn key_ok(key: &str) -> bool {
    (1..=32).contains(&key.len()) && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The typed value of state `key`, or `None`. An invalid key is `InvalidParam`; a value of
/// another type or range is `InvalidState`.
pub(crate) fn read<V: TryFrom<AllowitValue>>(state: &AllowitMap, key: &str) -> Result<Option<V>> {
    if !key_ok(key) {
        return Err(AllowitError::InvalidParam);
    }
    lookup(state, key)
        .map(|value| V::try_from(value).map_err(|_| AllowitError::InvalidState))
        .transpose()
}

/// Check a value's bounds: at most `MAX_ITEMS` values nested in it and `MAX_TEXT` bytes per
/// text. A larger or undecodable value is `InvalidParam`.
pub fn check_value(value: &AllowitValue) -> Result {
    nested(value, &mut 0)
}

/// Count the values nested in `value` into `total`, checking every bound on the way.
fn nested(value: &AllowitValue, total: &mut u32) -> Result {
    match value {
        AllowitValue::Str(text) if text_len(text) > MAX_TEXT => Err(AllowitError::InvalidParam),
        AllowitValue::List(items) => each_item(items, |item| {
            *total += 1;
            if *total > MAX_ITEMS {
                return Err(AllowitError::InvalidParam);
            }
            nested(&item, total)
        }),
        _ => Ok(()),
    }
}

/// Check a key => value map: at most `max` entries, valid keys and bounded values.
fn check_map(map: &AllowitMap, max: u32) -> Result {
    if count(map) > max {
        return Err(AllowitError::InvalidParam);
    }
    each_value(map, |value| check_value(&value))
}

/// Check owner params before storing them. A standard wallet admits only the canonical keys,
/// each with the type its rule decodes; Custom admits up to `MAX_PARAMS` keys with bounded
/// values, which its policy defines. A rejected map is `InvalidParam`.
pub fn check_params(params: &AllowitMap, tier: AllowitTier) -> Result {
    // Decode and bound every value first, so no later lookup meets an undecodable one.
    if tier == AllowitTier::Custom {
        return check_map(params, MAX_PARAMS);
    }
    check_map(params, RULES.len() as u32)?;
    let mut canonical = 0;
    for rule in RULES {
        if let Some(value) = lookup(params, rule.key()) {
            canonical += 1;
            canonical_value(rule, value)?;
        }
    }
    if canonical == count(params) {
        Ok(())
    } else {
        Err(AllowitError::InvalidParam)
    }
}

/// Decode a canonical param as its rule does, without request or state facts.
fn canonical_value(rule: AllowitRule, value: AllowitValue) -> Result {
    let value = Some(value);
    match rule {
        AllowitRule::call_cap | AllowitRule::expiry => int::<u64>(value).map(|_| ()),
        AllowitRule::recipients | AllowitRule::tokens => each_address(value, |_| ()),
        _ => cap(value).map(|_| ()),
    }
}

/// Check the agent's execution params: at most `MAX_ARGS` keys with bounded values.
pub fn check_args(args: &AllowitMap) -> Result {
    check_map(args, MAX_ARGS)
}

/// The integer of a set param: unset is `MissingParam`; another type or a value outside `T` is
/// `InvalidParam`.
fn int<T: TryFrom<i128>>(value: Option<AllowitValue>) -> Result<T> {
    match value.ok_or(AllowitError::MissingParam)? {
        AllowitValue::Int(n) => T::try_from(n).map_err(|_| AllowitError::InvalidParam),
        _ => Err(AllowitError::InvalidParam),
    }
}

/// A set cap: a nonnegative `Int`.
fn cap(value: Option<AllowitValue>) -> Result<i128> {
    let cap = int::<i128>(value)?;
    if cap < 0 {
        Err(AllowitError::InvalidParam)
    } else {
        Ok(cap)
    }
}

/// Run `seen` on each address of a set `List` of `Addr`; any other value is `InvalidParam`.
fn each_address(value: Option<AllowitValue>, mut seen: impl FnMut(Address)) -> Result {
    let AllowitValue::List(items) = value.ok_or(AllowitError::MissingParam)? else {
        return Err(AllowitError::InvalidParam);
    };
    each_item(&items, |item| match item {
        AllowitValue::Addr(address) => {
            seen(address);
            Ok(())
        }
        _ => Err(AllowitError::InvalidParam),
    })
}

/// Require `wanted` in a set allowlist. Every item must be an `Addr`; an empty list denies.
fn allowed(value: Option<AllowitValue>, wanted: &Address, denied: AllowitError) -> Result<Address> {
    let mut found = false;
    each_address(value, |address| found |= address == *wanted)?;
    if found {
        Ok(wanted.clone())
    } else {
        Err(denied)
    }
}

/// Checked sum of accounting values.
fn sum(a: i128, b: i128) -> Result<i128> {
    a.checked_add(b).ok_or(AllowitError::Overflow)
}

/// The request's own contribution: the sum of nonnegative request units.
fn contribution(parts: &[i128]) -> Result<i128> {
    parts.iter().try_fold(0, |total, part| {
        if *part < 0 {
            Err(AllowitError::InvalidParam)
        } else {
            sum(total, *part)
        }
    })
}

/// Standard values of the current state.
fn standard(ctx: &AllowitContext) -> Result<AllowitStandardState> {
    AllowitStandardState::read(&ctx.state)
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

/// Bound the gross amount of one operation by the cap in `value`.
///
/// Returns `cap - request.amount`. A negative cap or nonpositive amount is `InvalidParam`.
pub fn transaction_cap(ctx: &AllowitContext, value: Option<AllowitValue>) -> Result<i128> {
    let cap = cap(value)?;
    if ctx.request.amount <= 0 {
        return Err(AllowitError::InvalidParam);
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
pub fn spent_cap(ctx: &AllowitContext, value: Option<AllowitValue>) -> Result<i128> {
    let cap = cap(value)?;
    let (s, r) = (standard(ctx)?, &ctx.request);
    let add = contribution(&[r.spent_units]);
    let e = AllowitError::SpentCapExceeded;
    accounting(cap, s.spent, s.unpriced || r.unpriced, add, e)
}

/// Bound irreversible expenses on the request's UTC day: `day_spent + request.spent_units <= cap`.
/// `day_spent` is zero when the state belongs to an earlier day.
///
/// Returns the headroom left after this operation. Unpriced today or in the request is `Unpriced`.
pub fn day_spent_cap(ctx: &AllowitContext, value: Option<AllowitValue>) -> Result<i128> {
    let cap = cap(value)?;
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
pub fn day_total_cap(ctx: &AllowitContext, value: Option<AllowitValue>) -> Result<i128> {
    let cap = cap(value)?;
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
pub fn call_cap(ctx: &AllowitContext, value: Option<AllowitValue>) -> Result<u64> {
    let cap = int::<u64>(value)?;
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
pub fn recipients(ctx: &AllowitContext, value: Option<AllowitValue>) -> Result<Address> {
    let e = AllowitError::RecipientNotAllowed;
    allowed(value, &ctx.request.recipient, e)
}

/// Require an exact permitted underlying asset contract.
///
/// Returns the matched `request.asset`. An empty list denies.
pub fn tokens(ctx: &AllowitContext, value: Option<AllowitValue>) -> Result<Address> {
    allowed(value, &ctx.request.asset, AllowitError::TokenNotAllowed)
}

/// Require unexpired params and request, with the request expiring no later than the params.
///
/// Returns `expiry - request.now`, the seconds the params have left.
pub fn expiry(ctx: &AllowitContext, value: Option<AllowitValue>) -> Result<u64> {
    let expiry = int::<u64>(value)?;
    let r = &ctx.request;
    if r.now < expiry && r.now < r.expires_at && r.expires_at <= expiry {
        Ok(expiry - r.now)
    } else {
        Err(AllowitError::Expired)
    }
}

/// The value of owner param `key`, such as a custom `vendor_cap`. Unset is `MissingParam`.
pub fn param(ctx: &AllowitContext, key: &str) -> Result<AllowitValue> {
    ctx.params.get(key).ok_or(AllowitError::MissingParam)
}

/// The current value of a state key, before this operation, or `None`. Writes of this run apply
/// only in `post_flight`. A value of another type or range is `InvalidState`.
pub fn get_state<V: TryFrom<AllowitValue>>(ctx: &AllowitContext, key: &str) -> Result<Option<V>> {
    read(&ctx.state, key)
}

/// Record a policy write of `key`. `post_flight` applies it after the standard update, so it may
/// replace a standard key; standard wallets deny every write. A key is 1 to 32 ASCII letters,
/// digits or underscores, and the value stays within `check_value`.
pub fn set_state(ctx: &AllowitContext, key: &str, value: impl Into<AllowitValue>) -> Result {
    let value = value.into();
    check_value(&value)?;
    record(&ctx.env, key, value)
}

/// Standard-contract preflight of one canonical prefix call
/// `allowit::<rule>(ctx, ctx.params.get(allowit::<RULE>))?;`. Only this runner skips a rule whose
/// param is absent. It discards pass values.
pub fn preflight(ctx: &AllowitContext, rule: AllowitRule) -> Result {
    let Some(value) = ctx.params.get(rule.key()) else {
        return Ok(());
    };
    let value = Some(value);
    match rule {
        AllowitRule::transaction_cap => transaction_cap(ctx, value).map(|_| ()),
        AllowitRule::spent_cap => spent_cap(ctx, value).map(|_| ()),
        AllowitRule::day_spent_cap => day_spent_cap(ctx, value).map(|_| ()),
        AllowitRule::day_total_cap => day_total_cap(ctx, value).map(|_| ()),
        AllowitRule::call_cap => call_cap(ctx, value).map(|_| ()),
        AllowitRule::recipients => recipients(ctx, value).map(|_| ()),
        AllowitRule::tokens => tokens(ctx, value).map(|_| ()),
        AllowitRule::expiry => expiry(ctx, value).map(|_| ()),
    }
}

/// Standard values of `state` and its daily values on the request's day. A value of another type,
/// a negative amount or a later day is `InvalidState`.
fn decode(
    ctx: &AllowitContext,
    state: &AllowitMap,
) -> Result<(AllowitStandardState, (i128, i128, bool))> {
    let s = AllowitStandardState::read(state)?;
    let d = daily(ctx, &s)?;
    if s.spent < 0 || d.0 < 0 || d.1 < 0 {
        return Err(AllowitError::InvalidState);
    }
    Ok((s, d))
}

/// State after an approved operation, computed by the wallet and the server alike: roll the UTC
/// day over, count the call, add spent and gross amounts, mark an unpriced request, then apply the
/// policy's buffered writes. It clears the write buffer first, even when it fails.
///
/// A `Standard` wallet stores only the standard keys, so any policy write is `Unsupported`: the
/// host and the chain then store the same state for every tier. A result that later operations
/// could not decode, or whose totals leave no room for one more call or unit, is `InvalidState`,
/// so a policy write cannot make every later standard update fail.
pub fn post_flight(ctx: &AllowitContext, tier: AllowitTier) -> Result<AllowitMap> {
    let writes = take_writes(&ctx.env);
    if tier == AllowitTier::Standard && count(&writes) > 0 {
        return Err(AllowitError::Unsupported);
    }
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
    s.write(&mut state)?;
    merge(&mut state, writes);
    // The next standard update adds one call and may add a unit to each total.
    let (s, (day_spent, day_total, _)) = decode(ctx, &state)?;
    if s.calls == u64::MAX || [s.spent, day_spent, day_total].contains(&i128::MAX) {
        return Err(AllowitError::InvalidState);
    }
    Ok(state)
}

/// One policy evaluation, the server's entry point: clear stale writes, run `execute`, then
/// `post_flight` for the wallet's tier on approval. A denial discards the policy's writes, so no
/// write outlives it. The result is exactly the state the wallet stores.
pub fn evaluate(
    ctx: &AllowitContext,
    execute: impl FnOnce(&AllowitContext) -> Result,
    tier: AllowitTier,
) -> Result<AllowitMap> {
    take_writes(&ctx.env);
    let run = execute(ctx);
    if run.is_err() {
        take_writes(&ctx.env);
    }
    run.and_then(|()| post_flight(ctx, tier))
}
