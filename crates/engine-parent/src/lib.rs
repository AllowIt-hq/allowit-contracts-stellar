#![no_std]
use soroban_sdk::{
    Address, BytesN, ContractExecutable, ContractExecutableRef, Env, String, contract,
    contracterror, contractimpl, contracttype,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentState {
    /// Current engine-administrator address, authorized through native account or contract rules.
    pub owner: Address,
    /// Engine-administrator configuration sequence. It changes on parent administration and is not engine_version release metadata.
    pub version: u64,
    /// Shared veto-engine address. Engine approval cannot replace local policy checks or authorize owner administration.
    pub engine: Address,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    StaleVersion = 1,
    Overflow = 2,
    InvalidAdmin = 3,
}

#[contract]
pub struct EngineParent;

fn tag(env: &Env) -> String {
    String::from_str(env, "engine")
}
fn load(env: &Env, initial: Option<ParentState>) -> ParentState {
    if let Some(state) = initial {
        env.storage().instance().set(&0u32, &state);
    }
    let ttl = env.storage().max_ttl();
    env.deployer()
        .extend_ttl(env.current_contract_address(), ttl / 2, ttl);
    env.storage().instance().get(&0u32).unwrap()
}
fn save(env: &Env, state: &ParentState) {
    env.storage().instance().set(&0u32, state);
}
fn authorize(env: &Env, version: u64) -> Result<ParentState, Error> {
    let mut state = load(env, None);
    state.owner.require_auth();
    if state.version != version {
        return Err(Error::StaleVersion);
    }
    state.version = state.version.checked_add(1).ok_or(Error::Overflow)?;
    Ok(state)
}

// Engine maintenance is separate so parent administration can recover unavailable dependencies.
mod engine {
    use super::*;

    pub(super) fn load(env: &Env, address: Address) -> Address {
        let ttl = env.storage().max_ttl();
        env.deployer().extend_ttl(address.clone(), ttl / 2, ttl);
        address
    }
}

#[contractimpl]
impl EngineParent {
    /// Create the shared veto engine and its independent upgrade authority.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `owner`: Initial native or contract upgrade authority, distinct from parent and engine.
    /// - `engine_wasm`: Uploaded engine Wasm hash selected by that authority.
    ///
    /// # Returns
    /// Returns no value. Invalid roles or deployment failure roll back creation.
    pub fn __constructor(env: Env, owner: Address, engine_wasm: BytesN<32>) {
        owner.require_auth();
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
        load(
            &env,
            Some(ParentState {
                owner,
                version: 0,
                engine,
            }),
        );
    }

    /// Read engine-parent configuration.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns administrator, engine address and administrative version; no custody authority is granted.
    pub fn state(env: Env) -> ParentState {
        load(&env, None)
    }

    /// Read the engine address and refresh parent, engine and reference lifetimes.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns the shared veto address. It does not approve wallet spending.
    pub fn engine(env: Env) -> Address {
        engine::load(&env, load(&env, None).engine)
    }

    /// Replace shared engine executable bytes under current administrator authorization.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `new_hash`: Uploaded engine Wasm hash; its own release metadata is independent of this admin version.
    /// - `version`: Exact current parent administrative version, not a policy deployment or engine release version.
    ///
    /// # Returns
    /// Returns success after one administrative version increment and atomic reference update.
    pub fn upgrade_engine(env: Env, new_hash: BytesN<32>, version: u64) -> Result<(), Error> {
        let state = authorize(&env, version)?;
        // The host rejects hashes that do not identify uploaded Wasm.
        env.executable_refs().set(&tag(&env), &new_hash);
        save(&env, &state);
        Ok(())
    }

    /// Transfer engine upgrade administration with both authorities' authorization.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `owner`: Candidate native or contract administrator; it must accept the exact handoff.
    /// - `version`: Exact current parent administrative version.
    ///
    /// # Returns
    /// Returns success after the handoff and one version increment; wallet owner rights remain independent.
    pub fn set_admin(env: Env, owner: Address, version: u64) -> Result<(), Error> {
        let mut state = authorize(&env, version)?;
        if owner == env.current_contract_address() || owner == state.engine {
            return Err(Error::InvalidAdmin);
        }
        owner.require_auth();
        state.owner = owner;
        save(&env, &state);
        Ok(())
    }

    /// Upgrade parent code under its current independent administrator.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `new_hash`: Uploaded parent Wasm hash chosen by the administrator.
    /// - `version`: Exact current parent administrative version.
    ///
    /// # Returns
    /// Returns success after atomic code update and administrative version increment, or rolls back both.
    pub fn upgrade_parent(env: Env, new_hash: BytesN<32>, version: u64) -> Result<(), Error> {
        let state = authorize(&env, version)?;
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_hash));
        save(&env, &state);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
