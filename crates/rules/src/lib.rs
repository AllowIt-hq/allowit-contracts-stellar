#![no_std]
//! Canonical owner-policy rules shared by bundled code and the shared engine contract.
//! Each rule interprets only its selected keys. Unrelated native values remain unchanged.
use allowit_wallet_protocol::{EngineError as Error, EngineRequest, EngineResult, EngineState};
use soroban_sdk::xdr::{FromXdr, ToXdr};
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
fn nonnegative_limit(env: &Env, state: &EngineState, name: &str) -> Result<i128> {
    let raw = state
        .grant
        .get(key(env, name))
        .ok_or(Error::InvalidParameter)?;
    let amount = integer(env, &raw).ok_or(Error::InvalidParameter)?;
    if amount < 0 {
        Err(Error::InvalidParameter)
    } else {
        Ok(amount)
    }
}
fn addresses(env: &Env, raw: &Val) -> Result<Vec<Address>> {
    let values = Vec::<Val>::try_from_val(env, raw).map_err(|_| Error::InvalidParameter)?;
    let mut out = Vec::new(env);
    for value in values.iter() {
        out.push_back(Address::try_from_val(env, &value).map_err(|_| Error::InvalidParameter)?);
    }
    Ok(out)
}
fn disabled(env: &Env, state: &EngineState, name: &str) -> bool {
    state
        .grant
        .get(key(env, name))
        .is_none_or(|value| value.is_void())
}
/// Only canonical selected rules inspect their same-named owner parameter. Missing/Null disables that rule.
/// An unreadable Grant or incompatible non-Null selected value never becomes absence.
pub fn validate_rule(
    env: &Env,
    rule: &soroban_sdk::Symbol,
    grant: &allowit_wallet_protocol::Grant,
) -> Result<()> {
    let name = if *rule == soroban_sdk::Symbol::new(env, "transaction_cap") {
        "transaction_cap"
    } else if *rule == soroban_sdk::Symbol::new(env, "spent_cap") {
        "spent_cap"
    } else if *rule == soroban_sdk::Symbol::new(env, "day_spent_cap") {
        "day_spent_cap"
    } else if *rule == soroban_sdk::Symbol::new(env, "day_total_cap") {
        "day_total_cap"
    } else if *rule == soroban_sdk::Symbol::new(env, "call_cap") {
        "call_cap"
    } else if *rule == soroban_sdk::Symbol::new(env, "recipients") {
        "recipients"
    } else if *rule == soroban_sdk::Symbol::new(env, "expiry") {
        "expiry"
    } else if *rule == soroban_sdk::Symbol::new(env, "tokens") {
        "tokens"
    } else {
        return Err(Error::InvalidParameter);
    };
    let state = EngineState {
        grant: grant.clone(),
        spent: allowit_wallet_protocol::Spent::new(env),
    };
    if disabled(env, &state, name) {
        return Ok(());
    }
    match name {
        "transaction_cap" => {
            nonnegative_limit(env, &state, name)?;
        }
        "spent_cap" | "day_spent_cap" | "day_total_cap" => {
            nonnegative_limit(env, &state, name)?;
        }
        "call_cap" | "expiry" => {
            grant_u64(env, &state, name)?;
        }
        _ => {
            addresses(
                env,
                &grant.get(key(env, name)).ok_or(Error::InvalidParameter)?,
            )?;
        }
    }
    Ok(())
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

/// Return the server-attested cost ceiling after checking its native denomination and execution day.
/// Kernel operation validation distinguishes irreversible payments from retained deposit principal.
fn expenses(env: &Env, request: &EngineRequest) -> Result<allowit_wallet_protocol::ExpenseBounds> {
    let raw = request.expense.as_ref().ok_or(Error::InvalidParameter)?;
    if raw.len() > allowit_wallet_protocol::MAX_EXPENSE_BYTES {
        return Err(Error::InvalidParameter);
    }
    let value = allowit_wallet_protocol::ExpenseBounds::from_xdr(env, raw)
        .map_err(|_| Error::InvalidParameter)?;
    if value.clone().to_xdr(env) != *raw {
        return Err(Error::InvalidParameter);
    }
    if value.asset != request.asset
        || value.decimals != request.decimals
        || value.decimals != 7
        || value.gas_units < 0
        || value.conversion_units < 0
        || value.spent_units < 0
        || value.gas_units != i128::from(value.max_fee_stroops)
        || value.day != request.now / DAY
        || value.observed_ledger == 0
        || value.spent_units
            < value
                .gas_units
                .checked_add(value.conversion_units)
                .ok_or(Error::Overflow)?
    {
        return Err(Error::InvalidParameter);
    }
    Ok(value)
}
fn charge_named(
    env: &Env,
    request: EngineRequest,
    mut state: EngineState,
    cap: i128,
    amount: i128,
    usage: &str,
    marker: &str,
    facts_key: &str,
    day_key: Option<&str>,
) -> Result<EngineResult> {
    if cap < 0 || amount < 0 {
        return Err(Error::InvalidParameter);
    }
    let day = request.now / DAY;
    let previous_day = match day_key {
        Some(name) => spent_u64(env, &state, name, day)?,
        None => day,
    };
    if previous_day > day {
        return Err(Error::InvalidState);
    }
    let same_day = previous_day == day;
    if request.history.day != day
        || request.history.spent < 0
        || request.history.day_spent < 0
        || request.history.day_total < 0
    {
        return Err(Error::InvalidState);
    }
    let next = match usage {
        "spent" if !request.history.unpriced => request.history.spent,
        "day_spent" if !request.history.day_unpriced => request.history.day_spent,
        "day_total" if !request.history.day_unpriced => request.history.day_total,
        _ => return Err(Error::InvalidState),
    };
    let facts: Vec<Val> = (request.amount, request.expense.clone()).into_val(env);
    if same_day && charged(env, &request, &state, marker)? {
        let prior = state
            .spent
            .get(key(env, facts_key))
            .ok_or(Error::InvalidState)?;
        if Vec::<Val>::try_from_val(env, &prior).map_err(|_| Error::InvalidState)? != facts {
            return Err(Error::InvalidState);
        }
    }
    if next > cap {
        return Ok(result(state, false));
    }
    state.spent.set(key(env, usage), next.into_val(env));
    state.spent.set(key(env, facts_key), facts.into_val(env));
    state
        .spent
        .set(key(env, marker), request.operation_id.into_val(env));
    if let Some(name) = day_key {
        state.spent.set(key(env, name), day.into_val(env));
    }
    Ok(result(state, true))
}
/// Cumulative irreversible-expense ceiling. Grant spent_cap is nonnegative I128/U64 underlying units.
/// Spent spent/spent_operation preserve conservative server-approved expense ceilings without automatic refunds.
pub fn spent_cap(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    if disabled(&env, &state, "spent_cap") {
        return Ok(result(state, true));
    }
    valid_amount(&request)?;
    let amount = expenses(&env, &request)?.spent_units;
    let cap = nonnegative_limit(&env, &state, "spent_cap")?;
    charge_named(
        &env,
        request,
        state,
        cap,
        amount,
        "spent",
        "spent_operation",
        "spent_facts",
        None,
    )
}
/// UTC-day irreversible-expense ceiling. Grant day_spent_cap is nonnegative native underlying units.
/// Approval updates day_spent/day_spent_day/day_spent_operation. A backward stored day rejects.
pub fn day_spent_cap(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    if disabled(&env, &state, "day_spent_cap") {
        return Ok(result(state, true));
    }
    valid_amount(&request)?;
    let amount = expenses(&env, &request)?.spent_units;
    let cap = nonnegative_limit(&env, &state, "day_spent_cap")?;
    charge_named(
        &env,
        request,
        state,
        cap,
        amount,
        "day_spent",
        "day_spent_operation",
        "day_spent_facts",
        Some("day_spent_day"),
    )
}
/// UTC-day gross-notional ceiling. Underlying principal plus separate attributable gas counts once.
/// Embedded deposit conversion fees already belong to principal and are not added again.
pub fn day_total_cap(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    if disabled(&env, &state, "day_total_cap") {
        return Ok(result(state, true));
    }
    valid_amount(&request)?;
    let amount = request
        .amount
        .checked_add(expenses(&env, &request)?.gas_units)
        .ok_or(Error::Overflow)?;
    let cap = nonnegative_limit(&env, &state, "day_total_cap")?;
    charge_named(
        &env,
        request,
        state,
        cap,
        amount,
        "day_total",
        "day_total_operation",
        "day_total_facts",
        Some("day_total_day"),
    )
}
/// Authored exact SAC-address allowlist. Grant tokens is Vec<Address>, distinct from the old token label check.
pub fn tokens(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    if disabled(&env, &state, "tokens") {
        return Ok(result(state, true));
    }
    let raw = state
        .grant
        .get(key(&env, "tokens"))
        .ok_or(Error::InvalidParameter)?;
    let allowed = addresses(&env, &raw)?;
    Ok(result(state, allowed.contains(&request.asset)))
}

/// Run the explicitly selected transaction_cap rule.
///
/// Requires nonnegative Grant `transaction_cap` as U64 or I128 native base units and a positive request amount. Missing or invalid selected grant data returns InvalidParameter. Approval compares the amount to this cap. It reads no usage keys and returns the spent map unchanged.
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
    if disabled(&env, &state, "transaction_cap") {
        return Ok(result(state, true));
    }
    valid_amount(&request)?;
    let cap = nonnegative_limit(&env, &state, "transaction_cap")?;
    Ok(result(state, request.amount <= cap))
}

/// Run the explicitly selected call_cap rule.
///
/// Requires Grant `call_cap` as U64. Compares the proposed protected custody call count, including operations while this rule was disabled. Approval mirrors calls and the operation marker into authored Spent. Denial preserves the input map.
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
    if disabled(&env, &state, "call_cap") {
        return Ok(result(state, true));
    }
    let cap = grant_u64(&env, &state, "call_cap")?;
    let next = request.history.calls;
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
pub fn recipients(env: Env, request: EngineRequest, state: EngineState) -> Result<EngineResult> {
    if disabled(&env, &state, "recipients") {
        return Ok(result(state, true));
    }
    let raw = state
        .grant
        .get(key(&env, "recipients"))
        .ok_or(Error::InvalidParameter)?;
    let allowed = addresses(&env, &raw)?;
    Ok(result(state, allowed.contains(&request.recipient)))
}

/// Run the explicitly selected expiry rule.
///
/// Requires Grant `expiry` as U64 Unix ledger seconds. The request and grant must remain unexpired, and the request expiry cannot exceed the grant expiry. Missing or invalid grant data returns InvalidParameter. Denial leaves usage unchanged. Custody independently enforces request expiry even when this rule is not selected.
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
    if disabled(&env, &state, "expiry") {
        return Ok(result(state, true));
    }
    let expiry = grant_u64(&env, &state, "expiry")?;
    Ok(result(
        state,
        request.now < expiry && request.now < request.expires_at && request.expires_at <= expiry,
    ))
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
    if !params.is_empty() {
        return Err(Error::InvalidParameter);
    }
    match method {
        "transaction_cap" => transaction_cap(env.clone(), request, state),
        "spent_cap" => spent_cap(env.clone(), request, state),
        "day_spent_cap" => day_spent_cap(env.clone(), request, state),
        "day_total_cap" => day_total_cap(env.clone(), request, state),
        "call_cap" => call_cap(env.clone(), request, state),
        "recipients" => recipients(env.clone(), request, state),
        "expiry" => expiry(env.clone(), request, state),
        "tokens" => tokens(env.clone(), request, state),
        _ => Err(Error::InvalidParameter),
    }
}

#[cfg(test)]
mod tests;
