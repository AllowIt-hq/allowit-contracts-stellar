#![no_std]
//! Canonical owner-policy rules shared by bundled code and the shared engine contract.
//! Each rule interprets only its selected keys. Unrelated native values remain unchanged.
use allowit_wallet_protocol::{EngineError as Error, EngineRequest, EngineResult, EngineState};
use soroban_sdk::{Address, BytesN, Env, IntoVal, String, TryFromVal, Val, Vec};
type Result<T> = core::result::Result<T, Error>;
const DAY: u64 = 86_400;
fn result(state: EngineState, approval: bool) -> EngineResult {
    EngineResult {
        approval,
        spent: state.spent,
    }
}
fn key(env: &Env, name: &str) -> String {
    String::from_str(env, name)
}
fn integer(env: &Env, value: &Val) -> Option<i128> {
    i128::try_from_val(env, value)
        .ok()
        .or_else(|| u64::try_from_val(env, value).ok().map(i128::from))
}
fn limit(env: &Env, state: &EngineState, name: &str) -> Result<i128> {
    let value = state
        .grant
        .get(key(env, name))
        .ok_or(Error::InvalidParameter)?;
    let value = integer(env, &value).ok_or(Error::InvalidParameter)?;
    if value <= 0 {
        Err(Error::InvalidParameter)
    } else {
        Ok(value)
    }
}
/// Validate the native owner parameters required by one canonical zero-parameter rule.
/// Zero call capacity and an empty recipient list are valid deny-all configurations.
pub fn validate_rule(
    env: &Env,
    rule: &soroban_sdk::Symbol,
    grant: &allowit_wallet_protocol::Grant,
) -> Result<()> {
    let state = EngineState {
        grant: grant.clone(),
        spent: allowit_wallet_protocol::Spent::new(env),
    };
    for (name, parameter) in [
        ("transaction_cap", "per_transfer"),
        ("daily_cap", "daily_limit"),
        ("total_cap", "total_limit"),
    ] {
        if *rule == soroban_sdk::Symbol::new(env, name) {
            limit(env, &state, parameter)?;
            return Ok(());
        }
    }
    for (name, parameter) in [("call_cap", "max_calls"), ("expiry", "expires_at")] {
        if *rule == soroban_sdk::Symbol::new(env, name) {
            grant_u64(env, &state, parameter)?;
            return Ok(());
        }
    }
    if *rule == soroban_sdk::Symbol::new(env, "recipient") {
        let recipients = Vec::<Val>::try_from_val(
            env,
            &grant
                .get(key(env, "recipients"))
                .ok_or(Error::InvalidParameter)?,
        )
        .map_err(|_| Error::InvalidParameter)?;
        for recipient in recipients.iter() {
            Address::try_from_val(env, &recipient).map_err(|_| Error::InvalidParameter)?;
        }
    } else if *rule == soroban_sdk::Symbol::new(env, "token") {
        String::try_from_val(
            env,
            &grant
                .get(key(env, "token"))
                .ok_or(Error::InvalidParameter)?,
        )
        .map_err(|_| Error::InvalidParameter)?;
    } else {
        return Err(Error::InvalidParameter);
    }
    Ok(())
}
fn spent_amount(env: &Env, state: &EngineState, name: &str) -> Result<i128> {
    let Some(value) = state.spent.get(key(env, name)) else {
        return Ok(0);
    };
    let value = integer(env, &value).ok_or(Error::InvalidState)?;
    if value < 0 {
        Err(Error::InvalidState)
    } else {
        Ok(value)
    }
}
fn spent_u64(env: &Env, state: &EngineState, name: &str, default: u64) -> Result<u64> {
    state
        .spent
        .get(key(env, name))
        .map(|v| u64::try_from_val(env, &v).map_err(|_| Error::InvalidState))
        .unwrap_or(Ok(default))
}
fn grant_u64(env: &Env, state: &EngineState, name: &str) -> Result<u64> {
    u64::try_from_val(
        env,
        &state
            .grant
            .get(key(env, name))
            .ok_or(Error::InvalidParameter)?,
    )
    .map_err(|_| Error::InvalidParameter)
}
fn charged(env: &Env, request: &EngineRequest, state: &EngineState, name: &str) -> Result<bool> {
    state
        .spent
        .get(key(env, name))
        .map(|v| {
            BytesN::<32>::try_from_val(env, &v)
                .map(|v| v == request.operation_id)
                .map_err(|_| Error::InvalidState)
        })
        .unwrap_or(Ok(false))
}
fn valid_amount(request: &EngineRequest) -> Result<()> {
    if request.amount > 0 {
        Ok(())
    } else {
        Err(Error::InvalidParameter)
    }
}
fn expected_token(request: &EngineRequest, token: &String) -> Result<()> {
    if request.token == *token && request.decimals == 7 {
        Ok(())
    } else {
        Err(Error::InvalidParameter)
    }
}
fn daily(
    env: &Env,
    request: EngineRequest,
    mut state: EngineState,
    cap: i128,
) -> Result<EngineResult> {
    valid_amount(&request)?;
    if cap <= 0 {
        return Err(Error::InvalidParameter);
    }
    let day = request.now / DAY;
    let old_day = spent_u64(env, &state, "day", day)?;
    if old_day > day {
        return Err(Error::InvalidState);
    }
    let current = if old_day == day {
        spent_amount(env, &state, "daily")?
    } else {
        0
    };
    let already = old_day == day && charged(env, &request, &state, "daily_operation")?;
    let next = if already {
        current
    } else {
        current.checked_add(request.amount).ok_or(Error::Overflow)?
    };
    if next > cap {
        return Ok(result(state, false));
    }
    state.spent.set(key(env, "day"), day.into_val(env));
    state.spent.set(key(env, "daily"), next.into_val(env));
    state.spent.set(
        key(env, "daily_operation"),
        request.operation_id.into_val(env),
    );
    Ok(result(state, true))
}

/// Run the explicitly selected daily_cap rule.
///
/// Grant `daily_limit` is required, positive U64 or I128 native base units. Spent `day` is U64, `daily` is nonnegative U64 or I128, and `daily_operation` is Bytes32. Missing usage starts at zero and the current UTC day. A later UTC day resets daily usage, while a future stored day is invalid. An operation marker matching this request adds zero and rechecks the cap. Approval sets canonical I128 daily usage, U64 day and this operation ID in the returned map. Denial preserves the input map. Invalid grant types return InvalidParameter, invalid usage returns InvalidState, and checked addition can return Overflow.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn daily_cap(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    let cap = limit(&env, &state, "daily_limit")?;
    daily(&env, request, state, cap)
}

/// Run the explicitly selected transaction_cap rule.
///
/// Requires positive Grant `per_transfer` as U64 or I128 native base units and a positive request amount. Missing or invalid selected grant data returns InvalidParameter. Approval compares the amount to this cap. It reads no usage keys and returns the spent map unchanged.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn transaction_cap(
    env: Env,
    request: EngineRequest,
    state: EngineState,
) -> Result<EngineResult> {
    valid_amount(&request)?;
    let cap = limit(&env, &state, "per_transfer")?;
    Ok(result(state, request.amount <= cap))
}

/// Run the explicitly selected total_cap rule.
///
/// Requires positive Grant `total_limit` as U64 or I128 native base units. Spent `total` is nonnegative U64 or I128, default zero. `total_operation` is optional Bytes32. Matching operation identity adds zero and rechecks the cap. Approval sets canonical I128 total and this operation marker in the returned map. Denial preserves the input map. Invalid grant/usage and checked-add overflow return their respective errors.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn total_cap(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    valid_amount(&request)?;
    let cap = limit(&env, &state, "total_limit")?;
    let current = spent_amount(&env, &state, "total")?;
    let next = if charged(&env, &request, &state, "total_operation")? {
        current
    } else {
        current.checked_add(request.amount).ok_or(Error::Overflow)?
    };
    if next > cap {
        return Ok(result(state, false));
    }
    let mut state = state;
    state.spent.set(key(&env, "total"), next.into_val(&env));
    state.spent.set(
        key(&env, "total_operation"),
        request.operation_id.into_val(&env),
    );
    Ok(result(state, true))
}

/// Run the explicitly selected call_cap rule.
///
/// Requires Grant `max_calls` as U64. Spent `calls` is U64, default zero, and `call_operation` is optional Bytes32. A new operation adds one call, while a matching marker adds zero and rechecks the cap. Zero capacity denies. Approval sets calls and the operation marker in the returned map. Denial preserves the input map. Invalid types and checked-add overflow return errors.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn call_cap(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    let cap = grant_u64(&env, &state, "max_calls")?;
    let current = spent_u64(&env, &state, "calls", 0)?;
    let next = if charged(&env, &request, &state, "call_operation")? {
        current
    } else {
        current.checked_add(1).ok_or(Error::Overflow)?
    };
    if cap == 0 || next > cap {
        return Ok(result(state, false));
    }
    let mut state = state;
    state.spent.set(key(&env, "calls"), next.into_val(&env));
    state.spent.set(
        key(&env, "call_operation"),
        request.operation_id.into_val(&env),
    );
    Ok(result(state, true))
}

/// Run the explicitly selected recipient rule.
///
/// Requires Grant `recipients` as Vec<Address>. Missing or wrong types return InvalidParameter. Empty lists or a nonmatching request recipient return false. No usage key changes. Custody separately enforces the exact transfer destination and rejects self-payment.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn recipient(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    let raw = state
        .grant
        .get(key(&env, "recipients"))
        .ok_or(Error::InvalidParameter)?;
    let allowed = Vec::<Address>::try_from_val(&env, &raw).map_err(|_| Error::InvalidParameter)?;
    Ok(result(state, allowed.contains(&request.recipient)))
}

/// Run the explicitly selected expiry rule.
///
/// Requires Grant `expires_at` as U64 Unix ledger seconds. The request and grant must remain unexpired, and the request expiry cannot exceed the grant expiry. Missing or invalid grant data returns InvalidParameter. Denial leaves usage unchanged. Custody independently enforces request expiry even when this rule is not selected.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn expiry(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    let expiry = grant_u64(&env, &state, "expires_at")?;
    Ok(result(
        state,
        request.now < expiry && request.now < request.expires_at && request.expires_at <= expiry,
    ))
}

/// Run the explicitly selected token rule.
///
/// Requires Grant `token` as a native String. It compares the authenticated label and requires the seven-decimal custody profile. Missing or invalid selected grant data returns InvalidParameter; a mismatch returns false. Labels do not replace the immutable SAC address identity. No usage key changes.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn token(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    let raw = state
        .grant
        .get(key(&env, "token"))
        .ok_or(Error::InvalidParameter)?;
    let expected = String::try_from_val(&env, &raw).map_err(|_| Error::InvalidParameter)?;
    Ok(result(
        state,
        request.decimals == 7 && request.token == expected,
    ))
}

/// Run the explicitly selected cap_per_transaction rule.
///
/// Uses only the explicit positive I128 limit and authenticated token label, not any Grant key. Token or decimal mismatch, invalid amount or invalid limit returns InvalidParameter. An exceeded bound returns false. No usage key changes.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
/// - `limit`: Positive cap in native i128 asset base units.
/// - `token`: Expected authenticated SAC label.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn cap_per_transaction(
    env: Env,
    request: EngineRequest,
    state: EngineState,
    limit: i128,
    token: String,
) -> Result<EngineResult> {
    let _ = env;
    valid_amount(&request)?;
    expected_token(&request, &token)?;
    if limit <= 0 {
        return Err(Error::InvalidParameter);
    }
    Ok(result(state, request.amount <= limit))
}

/// Run the explicitly selected cap_per_day rule.
///
/// Uses the explicit positive I128 limit and token label without reading Grant daily_limit. The spent keys, UTC rollover and once-per-operation behavior are identical to daily_cap, including the shared daily_operation marker. Token or decimal mismatch returns InvalidParameter.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
/// - `limit`: Positive cap in native i128 asset base units.
/// - `token`: Expected authenticated SAC label.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn cap_per_day(
    env: Env,
    request: EngineRequest,
    state: EngineState,
    limit: i128,
    token: String,
) -> Result<EngineResult> {
    expected_token(&request, &token)?;
    daily(&env, request, state, limit)
}

/// Run the explicitly selected recipient_is rule.
///
/// Uses the explicit expected address and no Grant key. A mismatch returns false. The spent map is returned unchanged.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
/// - `expected`: Exact expected native address or authenticated label.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn recipient_is(
    env: Env,
    request: EngineRequest,
    state: EngineState,
    expected: Address,
) -> Result<EngineResult> {
    let _ = env;
    Ok(result(state, request.recipient == expected))
}

/// Run the explicitly selected asset_label rule.
///
/// Uses the explicit expected token label and the authenticated seven-decimal profile, with no Grant key. A mismatch returns false. This label check does not replace custody SAC address binding. The spent map is unchanged.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
/// - `expected`: Exact expected native address or authenticated label.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn asset_label(
    env: Env,
    request: EngineRequest,
    state: EngineState,
    expected: String,
) -> Result<EngineResult> {
    let _ = env;
    Ok(result(
        state,
        request.decimals == 7 && request.token == expected,
    ))
}

/// Run the explicitly selected actions rule.
///
/// Uses the explicit allowed list and no Grant key. This custody profile admits only stellar::sep41_transfer, so approval requires that exact identifier in the list. No usage key changes.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
/// - `allowed`: Explicitly permitted action identifiers.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn actions(
    env: Env,
    request: EngineRequest,
    state: EngineState,
    allowed: Vec<String>,
) -> Result<EngineResult> {
    let _ = request;
    Ok(result(
        state,
        allowed.contains(String::from_str(&env, "stellar::sep41_transfer")),
    ))
}

/// Run the explicitly selected amount_at_most rule.
///
/// Uses the explicit nonnegative I128 bound and authenticated token label, not Grant keys. A greater positive amount returns ordinary false, including a zero bound, so source may handle that predicate branch. Invalid amount, negative bound, token or decimal mismatch returns InvalidParameter rather than false. No usage key changes.
/// Unrelated Grant and Spent entries are preserved without coercion.
///
/// # Parameters
/// - `env`: Native value environment supplied by the invoking wrapper.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Complete immutable grant and current mutable spent copies.
/// - `limit`: Nonnegative bound in native i128 asset base units.
/// - `token`: Expected authenticated SAC label.
///
/// # Returns
/// Returns a predicate decision and proposed spent map. Invalid state or parameters return an error.
pub fn amount_at_most(
    env: Env,
    request: EngineRequest,
    state: EngineState,
    limit: i128,
    token: String,
) -> Result<EngineResult> {
    let _ = env;
    valid_amount(&request)?;
    expected_token(&request, &token)?;
    if limit < 0 {
        return Err(Error::InvalidParameter);
    }
    Ok(result(state, request.amount <= limit))
}

/// Execute a compiler-selected local rule with the same arguments as the shared contract ABI.
/// # Parameters
/// - `env`: Host-provided native value environment.
/// - `request`: Exact custody-authenticated proposal and operation identity.
/// - `state`: Full grant and current spent copies.
/// - `method`: Fixed compiler-admitted rule selector; unknown selectors reject.
/// - `params`: Exact typed extra arguments emitted by the compiler; extra or missing arguments reject.
/// # Returns
/// Returns the canonical rule result. It never falls back to another placement or grants token authority.
pub fn check(
    env: &Env,
    request: EngineRequest,
    state: EngineState,
    method: &str,
    params: Vec<Val>,
) -> Result<EngineResult> {
    match method {
        "daily_cap" if params.is_empty() => daily_cap(env.clone(), request, state),
        "transaction_cap" if params.is_empty() => transaction_cap(env.clone(), request, state),
        "total_cap" if params.is_empty() => total_cap(env.clone(), request, state),
        "call_cap" if params.is_empty() => call_cap(env.clone(), request, state),
        "recipient" if params.is_empty() => recipient(env.clone(), request, state),
        "expiry" if params.is_empty() => expiry(env.clone(), request, state),
        "token" if params.is_empty() => token(env.clone(), request, state),
        "cap_per_transaction" if params.len() == 2 => cap_per_transaction(
            env.clone(),
            request,
            state,
            arg::<i128>(env, &params, 0)?,
            arg::<String>(env, &params, 1)?,
        ),
        "cap_per_day" if params.len() == 2 => cap_per_day(
            env.clone(),
            request,
            state,
            arg::<i128>(env, &params, 0)?,
            arg::<String>(env, &params, 1)?,
        ),
        "recipient_is" if params.len() == 1 => recipient_is(
            env.clone(),
            request,
            state,
            arg::<Address>(env, &params, 0)?,
        ),
        "asset_label" if params.len() == 1 => {
            asset_label(env.clone(), request, state, arg::<String>(env, &params, 0)?)
        }
        "actions" if params.len() == 1 => actions(
            env.clone(),
            request,
            state,
            arg::<Vec<String>>(env, &params, 0)?,
        ),
        "amount_at_most" if params.len() == 2 => amount_at_most(
            env.clone(),
            request,
            state,
            arg::<i128>(env, &params, 0)?,
            arg::<String>(env, &params, 1)?,
        ),
        _ => Err(Error::InvalidParameter),
    }
}
fn arg<T: TryFromVal<Env, Val>>(env: &Env, params: &Vec<Val>, i: u32) -> Result<T> {
    T::try_from_val(env, &params.get(i).ok_or(Error::InvalidParameter)?)
        .map_err(|_| Error::InvalidParameter)
}
#[cfg(test)]
mod tests;
