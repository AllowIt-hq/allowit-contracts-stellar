#![no_std]
use soroban_sdk::{
    Address, BytesN, ContractExecutable, ContractExecutableRef, Env, String, contract,
    contracterror, contractimpl, contracttype,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentState {
    pub upgrade_authority: Address,
    pub revision: u64,
    pub engine: Address,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    StaleRevision = 1,
    Overflow = 2,
    InvalidAdmin = 3,
}

#[contract]
pub struct EngineParent;

fn tag(env: &Env) -> String {
    String::from_str(env, "engine")
}
fn load(env: &Env) -> ParentState {
    let ttl = env.storage().max_ttl();
    env.deployer()
        .extend_ttl(env.current_contract_address(), ttl / 2, ttl);
    env.storage().instance().get(&0u32).unwrap()
}
fn save(env: &Env, state: &ParentState) {
    env.storage().instance().set(&0u32, state);
    let ttl = env.storage().max_ttl();
    env.storage().instance().extend_ttl(ttl / 2, ttl);
}
fn authorize(env: &Env, expected_revision: u64) -> Result<ParentState, Error> {
    let mut state = load(env);
    state.upgrade_authority.require_auth();
    if state.revision != expected_revision {
        return Err(Error::StaleRevision);
    }
    state.revision = state.revision.checked_add(1).ok_or(Error::Overflow)?;
    Ok(state)
}

#[contractimpl]
impl EngineParent {
    pub fn __constructor(env: Env, admin: Address, engine_wasm: BytesN<32>) {
        if admin == env.current_contract_address() {
            soroban_sdk::panic_with_error!(&env, Error::InvalidAdmin);
        }
        admin.require_auth();
        env.executable_refs().set(&tag(&env), &engine_wasm);
        let engine = env
            .deployer()
            .with_current_contract(BytesN::from_array(&env, &[0; 32]))
            .deploy_contract(
                ContractExecutable::ExternalRef(ContractExecutableRef {
                    owner: env.current_contract_address(),
                    tag: tag(&env),
                }),
                (),
            );
        if admin == engine {
            soroban_sdk::panic_with_error!(&env, Error::InvalidAdmin);
        }
        save(
            &env,
            &ParentState {
                upgrade_authority: admin,
                revision: 0,
                engine,
            },
        );
    }

    pub fn state(env: Env) -> ParentState {
        load(&env)
    }

    pub fn engine(env: Env) -> Address {
        let state = load(&env);
        let ttl = env.storage().max_ttl();
        env.executable_refs().extend_ttl(&tag(&env), ttl / 2, ttl);
        env.deployer()
            .extend_ttl(state.engine.clone(), ttl / 2, ttl);
        state.engine
    }

    pub fn upgrade_engine(
        env: Env,
        new_hash: BytesN<32>,
        expected_revision: u64,
    ) -> Result<(), Error> {
        let state = authorize(&env, expected_revision)?;
        // The host rejects hashes that do not identify uploaded Wasm.
        env.executable_refs().set(&tag(&env), &new_hash);
        save(&env, &state);
        Ok(())
    }

    pub fn set_admin(env: Env, new_admin: Address, expected_revision: u64) -> Result<(), Error> {
        let mut state = authorize(&env, expected_revision)?;
        if new_admin == env.current_contract_address() || new_admin == state.engine {
            return Err(Error::InvalidAdmin);
        }
        new_admin.require_auth();
        state.upgrade_authority = new_admin;
        save(&env, &state);
        Ok(())
    }

    pub fn upgrade_parent(
        env: Env,
        new_hash: BytesN<32>,
        expected_revision: u64,
    ) -> Result<(), Error> {
        let state = authorize(&env, expected_revision)?;
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_hash));
        save(&env, &state);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
