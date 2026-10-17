#![no_std]

use allowit_wallet_protocol::{
    EngineClient, EngineContext, Grant, MAX_RECIPIENTS, TransferRequest,
};
use soroban_sdk::{
    Address, BytesN, Env, Executable, contract, contracterror, contractimpl, contracttype, token,
};

const DAY: u64 = 86_400;
const VERSION: u32 = 1;
const TTL_THRESHOLD: u32 = 100_000;
const TTL_EXTEND: u32 = 200_000;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub version: u32,
    pub owner: Address,
    pub agent: Address,
    pub engine: Address,
    pub grant: Grant,
    pub spent_daily: i128,
    pub spent_day: u64,
    pub spent_total: i128,
    pub calls: u64,
    pub nonce: u64,
    pub revision: u64,
    pub paused: bool,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    InvalidState = 1,
    InvalidGrant = 2,
    UnsupportedAsset = 3,
    InvalidActor = 4,
    StaleRequest = 5,
    Paused = 6,
    Expired = 7,
    InvalidAmount = 8,
    InvalidRecipient = 9,
    BudgetExceeded = 10,
    Overflow = 11,
    ClockRegression = 12,
    EngineDenied = 13,
    InsufficientFunds = 14,
    InvalidEffects = 15,
    UnsupportedOperation = 16,
}

#[contract]
pub struct Odc;

fn load(env: &Env) -> Result<State, Error> {
    let s: State = env
        .storage()
        .instance()
        .get(&0u32)
        .ok_or(Error::InvalidState)?;
    if s.version != VERSION {
        return Err(Error::InvalidState);
    }
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
    Ok(s)
}

fn store(env: &Env, state: &State) {
    env.storage().instance().set(&0u32, state);
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
}

fn changed(s: &mut State) -> Result<(), Error> {
    s.revision = s.revision.checked_add(1).ok_or(Error::Overflow)?;
    Ok(())
}

fn owner_state(env: &Env, expected_revision: u64) -> Result<State, Error> {
    let s = load(env)?;
    s.owner.require_auth();
    if s.revision != expected_revision {
        return Err(Error::StaleRequest);
    }
    Ok(s)
}

fn validate_roles(
    env: &Env,
    owner: &Address,
    agent: &Address,
    engine: &Address,
) -> Result<(), Error> {
    let wallet = env.current_contract_address();
    if owner == agent
        || owner == engine
        || agent == engine
        || owner == &wallet
        || agent == &wallet
        || engine == &wallet
    {
        return Err(Error::InvalidActor);
    }
    Ok(())
}

fn validate_grant(env: &Env, grant: &Grant) -> Result<(), Error> {
    if grant.recipients.is_empty()
        || grant.recipients.len() > MAX_RECIPIENTS
        || grant.per_transfer <= 0
        || grant.daily_limit <= 0
        || grant.total_limit <= 0
        || grant.max_calls == 0
        || grant.expires_at <= env.ledger().timestamp()
    {
        return Err(Error::InvalidGrant);
    }
    for (i, recipient) in grant.recipients.iter().enumerate() {
        if recipient == env.current_contract_address() {
            return Err(Error::InvalidRecipient);
        }
        for prior in grant.recipients.iter().take(i) {
            if prior == recipient {
                return Err(Error::InvalidGrant);
            }
        }
    }
    Ok(())
}

fn move_tokens(env: &Env, asset: &Address, recipient: &Address, amount: i128) -> Result<(), Error> {
    if amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    if recipient == &env.current_contract_address() {
        return Err(Error::InvalidRecipient);
    }
    let client = token::Client::new(env, asset);
    let from = env.current_contract_address();
    let before_from = client.balance(&from);
    let before_to = client.balance(recipient);
    if before_from < amount {
        return Err(Error::InsufficientFunds);
    }
    let after_from = before_from.checked_sub(amount).ok_or(Error::Overflow)?;
    let after_to = before_to.checked_add(amount).ok_or(Error::Overflow)?;
    // Only this exact direct SAC transfer receives the ODC's invoker authority.
    // No authority is delegated to the engine or to arbitrary nested calls.
    client.transfer(&from, recipient, &amount);
    if client.balance(&from) != after_from || client.balance(recipient) != after_to {
        return Err(Error::InvalidEffects);
    }
    Ok(())
}

#[contractimpl]
impl Odc {
    pub fn __constructor(env: Env, owner: Address, agent: Address, engine: Address, grant: Grant) {
        owner.require_auth();
        if let Err(error) = validate_roles(&env, &owner, &agent, &engine) {
            soroban_sdk::panic_with_error!(&env, error);
        }
        if grant.asset.executable() != Some(Executable::StellarAsset)
            || token::Client::new(&env, &grant.asset).decimals() != 7
        {
            soroban_sdk::panic_with_error!(&env, Error::UnsupportedAsset);
        }
        if let Err(error) = validate_grant(&env, &grant) {
            soroban_sdk::panic_with_error!(&env, error);
        }
        store(
            &env,
            &State {
                version: VERSION,
                owner,
                agent,
                engine,
                grant,
                spent_daily: 0,
                spent_day: env.ledger().timestamp() / DAY,
                spent_total: 0,
                calls: 0,
                nonce: 0,
                revision: 0,
                paused: false,
            },
        );
    }

    pub fn state(env: Env) -> Result<State, Error> {
        load(&env)
    }

    pub fn transfer(env: Env, request: TransferRequest) -> Result<(), Error> {
        let mut s = load(&env)?;
        s.agent.require_auth();
        if s.paused {
            return Err(Error::Paused);
        }
        if request.nonce != s.nonce || request.revision != s.revision {
            return Err(Error::StaleRequest);
        }
        let now = env.ledger().timestamp();
        if request.expires_at <= now || s.grant.expires_at <= now {
            return Err(Error::Expired);
        }
        if request.amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        if !s.grant.recipients.contains(&request.recipient)
            || request.recipient == env.current_contract_address()
        {
            return Err(Error::InvalidRecipient);
        }
        let day = now / DAY;
        if day < s.spent_day {
            return Err(Error::ClockRegression);
        }
        let spent_daily = if day == s.spent_day { s.spent_daily } else { 0 };
        let next_daily = spent_daily
            .checked_add(request.amount)
            .ok_or(Error::Overflow)?;
        let next_total = s
            .spent_total
            .checked_add(request.amount)
            .ok_or(Error::Overflow)?;
        let next_calls = s.calls.checked_add(1).ok_or(Error::Overflow)?;
        let next_nonce = s.nonce.checked_add(1).ok_or(Error::Overflow)?;
        if request.amount > s.grant.per_transfer
            || next_daily > s.grant.daily_limit
            || next_total > s.grant.total_limit
            || next_calls > s.grant.max_calls
        {
            return Err(Error::BudgetExceeded);
        }
        let context = EngineContext {
            wallet: env.current_contract_address(),
            agent: s.agent.clone(),
            asset: s.grant.asset.clone(),
            request: request.clone(),
            grant: s.grant.clone(),
            spent_daily,
            spent_total: s.spent_total,
            calls: s.calls,
            now,
        };
        if !matches!(
            EngineClient::new(&env, &s.engine).try_evaluate(&context),
            Ok(Ok(true))
        ) {
            return Err(Error::EngineDenied);
        }
        // Commit local counters before the effect; host rollback restores them if
        // the SAC transfer or exact balance-effect check fails.
        s.spent_daily = next_daily;
        s.spent_day = day;
        s.spent_total = next_total;
        s.calls = next_calls;
        s.nonce = next_nonce;
        store(&env, &s);
        move_tokens(&env, &s.grant.asset, &request.recipient, request.amount)?;
        Ok(())
    }

    pub fn set_grant(env: Env, grant: Grant, expected_revision: u64) -> Result<(), Error> {
        let mut s = owner_state(&env, expected_revision)?;
        if grant.asset != s.grant.asset {
            return Err(Error::UnsupportedAsset);
        }
        validate_grant(&env, &grant)?;
        s.grant = grant;
        changed(&mut s)?;
        store(&env, &s);
        Ok(())
    }

    pub fn set_engine(env: Env, engine: Address, expected_revision: u64) -> Result<(), Error> {
        let mut s = owner_state(&env, expected_revision)?;
        validate_roles(&env, &s.owner, &s.agent, &engine)?;
        s.engine = engine;
        changed(&mut s)?;
        store(&env, &s);
        Ok(())
    }

    pub fn set_agent(env: Env, agent: Address, expected_revision: u64) -> Result<(), Error> {
        let mut s = owner_state(&env, expected_revision)?;
        validate_roles(&env, &s.owner, &agent, &s.engine)?;
        s.agent = agent;
        changed(&mut s)?;
        store(&env, &s);
        Ok(())
    }

    pub fn set_paused(env: Env, paused: bool, expected_revision: u64) -> Result<(), Error> {
        let mut s = owner_state(&env, expected_revision)?;
        s.paused = paused;
        changed(&mut s)?;
        store(&env, &s);
        Ok(())
    }

    pub fn transfer_owner(
        env: Env,
        new_owner: Address,
        expected_revision: u64,
    ) -> Result<(), Error> {
        let mut s = owner_state(&env, expected_revision)?;
        if new_owner == s.owner {
            return Err(Error::InvalidActor);
        }
        validate_roles(&env, &new_owner, &s.agent, &s.engine)?;
        new_owner.require_auth();
        s.owner = new_owner;
        changed(&mut s)?;
        store(&env, &s);
        Ok(())
    }

    pub fn upgrade(
        env: Env,
        new_wasm_hash: BytesN<32>,
        expected_revision: u64,
    ) -> Result<(), Error> {
        let mut s = owner_state(&env, expected_revision)?;
        changed(&mut s)?;
        store(&env, &s);
        env.deployer()
            .update_current_contract(soroban_sdk::ContractExecutable::Wasm(new_wasm_hash));
        Ok(())
    }

    pub fn recover(
        env: Env,
        recipient: Address,
        amount: i128,
        expected_revision: u64,
    ) -> Result<(), Error> {
        let mut s = owner_state(&env, expected_revision)?;
        changed(&mut s)?;
        store(&env, &s);
        move_tokens(&env, &s.grant.asset, &recipient, amount)
    }

    /// General calls and arbitrary authorization are outside this transfer-only ABI.
    pub fn unsupported(_env: Env) -> Result<(), Error> {
        Err(Error::UnsupportedOperation)
    }
}

#[cfg(test)]
mod tests;
