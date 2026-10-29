#![no_std]
use soroban_sdk::{
    Address, BytesN, ContractExecutable, ContractExecutableRef, Env, String, contract,
    contracterror, contractimpl, contracttype,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParentState {
    /// Current engine-administrator address, authorized through native account or contract rules.
    pub upgrade_authority: Address,
    /// Engine-administrator configuration sequence. It changes on parent administration and is not engine_version release metadata.
    pub revision: u64,
    /// Shared veto-engine address. Engine approval cannot replace local policy checks or authorize owner administration.
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
    /// Create the shared veto engine and its independent upgrade authority.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `admin`: Initial native or contract upgrade authority, distinct from parent and engine.
    /// - `engine_wasm`: Uploaded engine Wasm hash selected by that authority.
    ///
    /// # Returns
    /// Returns no value. Invalid roles or deployment failure roll back creation.
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

    /// Read engine-parent configuration.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns administrator, engine address and administrative revision; no custody authority is granted.
    pub fn state(env: Env) -> ParentState {
        load(&env)
    }

    /// Read the engine address and refresh parent, engine and reference lifetimes.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    ///
    /// # Returns
    /// Returns the shared veto address. It does not approve wallet spending.
    pub fn engine(env: Env) -> Address {
        let state = load(&env);
        let ttl = env.storage().max_ttl();
        env.executable_refs().extend_ttl(&tag(&env), ttl / 2, ttl);
        env.deployer()
            .extend_ttl(state.engine.clone(), ttl / 2, ttl);
        state.engine
    }

    /// Replace shared engine executable bytes under current administrator authorization.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `new_hash`: Uploaded engine Wasm hash; its own release metadata is independent of this admin revision.
    /// - `expected_revision`: Exact current parent administrative revision, not a policy deployment or engine release version.
    ///
    /// # Returns
    /// Returns success after one administrative revision increment and atomic reference update.
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

    /// Transfer engine upgrade administration with both authorities' authorization.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `new_admin`: Candidate native or contract administrator; it must accept the exact handoff.
    /// - `expected_revision`: Exact current parent administrative revision.
    ///
    /// # Returns
    /// Returns success after the handoff and one revision increment; wallet owner rights remain independent.
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

    /// Upgrade parent code under its current independent administrator.
    ///
    /// # Parameters
    /// - `env`: Host-provided execution environment; callers do not serialize this argument.
    /// - `new_hash`: Uploaded parent Wasm hash chosen by the administrator.
    /// - `expected_revision`: Exact current parent administrative revision.
    ///
    /// # Returns
    /// Returns success after atomic code update and administrative revision increment, or rolls back both.
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
