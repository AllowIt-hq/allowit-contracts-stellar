#![no_std]
//! Test-only hostile SEP-56 vault. Never use this fixture as a deployed asset vault.
use soroban_sdk::{Address, BytesN, ContractExecutable, Env, contract, contractimpl, token};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    pub fn __constructor(env: Env, asset: Address, behavior: u32) {
        env.storage().instance().set(&0u32, &asset);
        env.storage().instance().set(&1u32, &behavior);
    }
    pub fn query_asset(env: Env) -> Address {
        env.storage().instance().get(&0u32).unwrap()
    }
    pub fn set_upgrade(env: Env, hash: BytesN<32>) {
        env.storage().instance().set(&2u32, &hash);
    }
    pub fn balance(env: Env, owner: Address) -> i128 {
        env.storage().persistent().get(&owner).unwrap_or(0)
    }
    pub fn deposit(
        env: Env,
        assets: i128,
        receiver: Address,
        from: Address,
        operator: Address,
    ) -> i128 {
        operator.require_auth();
        from.require_auth();
        let asset: Address = env.storage().instance().get(&0u32).unwrap();
        let behavior: u32 = env.storage().instance().get(&1u32).unwrap();
        let vault = env.current_contract_address();
        let token = token::Client::new(&env, &asset);
        let debit = if behavior == 3 {
            assets + 1
        } else if behavior == 4 {
            assets - 1
        } else {
            assets
        };
        token.transfer(&from, &vault, &debit);
        if behavior == 7 {
            // A second gross debit followed by a refund must fail even though net balance would match.
            token.transfer(&from, &vault, &assets);
            token.transfer(&vault, &from, &assets);
        }
        if behavior == 8 {
            let hash: BytesN<32> = env.storage().instance().get(&2u32).unwrap();
            env.deployer()
                .update_current_contract(ContractExecutable::Wasm(hash));
        }
        if behavior == 5 {
            // A persistent approval must never inherit the exact deeper transfer authorization.
            token.approve(&from, &vault, &1, &1_000_000);
        }
        let shares = if behavior == 1 { assets - 1 } else { assets };
        let credit = if behavior == 2 { shares - 1 } else { shares };
        let before = Self::balance(env.clone(), receiver.clone());
        env.storage()
            .persistent()
            .set(&receiver, &(before + credit));
        if behavior == 6 {
            env.storage().instance().set(&0u32, &vault);
        }
        shares
    }
}
