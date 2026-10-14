#![no_std]
use soroban_sdk::{Address, BytesN, ContractExecutable, Env, contract, contractimpl};

#[contract]
pub struct Factory;
#[contractimpl]
impl Factory {
    pub fn __constructor(env: Env, vault_wasm: BytesN<32>) {
        env.storage().instance().set(&0u32, &vault_wasm);
    }
    pub fn create(
        env: Env,
        salt: BytesN<32>,
        owner: Address,
        executor: Address,
        authority: Address,
        asset: Address,
        policy: Address,
        policy_source: BytesN<32>,
        policy_wasm: BytesN<32>,
        daily_limit: u64,
    ) -> Address {
        owner.require_auth();
        env.storage().instance().extend_ttl(100_000, 200_000);
        let wasm: BytesN<32> = env.storage().instance().get(&0u32).unwrap();
        // Bind the salt to the authenticated owner to prevent address squatting.
        let salt = env
            .crypto()
            .sha256(&(owner.clone(), salt).to_xdr(&env))
            .to_bytes();
        env.deployer().with_current_contract(salt).deploy_contract(
            ContractExecutable::Wasm(wasm),
            (
                owner,
                executor,
                authority,
                asset,
                policy,
                policy_source,
                policy_wasm,
                daily_limit,
            ),
        )
    }
}
use soroban_sdk::xdr::ToXdr;

#[cfg(test)]
mod tests {
    use super::*;
    use allowit_policy::NativePolicyClient;
    use allowit_vault::VaultClient;
    use soroban_sdk::{Bytes, address_payload::AddressPayload, testutils::Address as _};
    const VAULT_WASM: &[u8] =
        include_bytes!("../../../target/wasm32v1-none/release/allowit_vault.wasm");
    const POLICY_WASM: &[u8] =
        include_bytes!("../../../target/wasm32v1-none/release/allowit_policy.wasm");
    #[test]
    fn factory_creates_compiled_vaults_with_owner_bound_salts() {
        let env = Env::default();
        env.mock_all_auths();
        let owner = Address::generate(&env);
        let other = Address::generate(&env);
        let executor = Address::from_payload(
            &env,
            AddressPayload::AccountIdPublicKeyEd25519(BytesN::from_array(&env, &[2; 32])),
        );
        let authority = Address::from_payload(
            &env,
            AddressPayload::AccountIdPublicKeyEd25519(BytesN::from_array(&env, &[3; 32])),
        );
        let asset = env
            .register_stellar_asset_contract_v2(owner.clone())
            .address();
        let policy = env.register(POLICY_WASM, ());
        let source = NativePolicyClient::new(&env, &policy).source_hash();
        let policy_wasm = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, POLICY_WASM))
            .to_bytes();
        let vault_wasm = env
            .deployer()
            .upload_contract_wasm(Bytes::from_slice(&env, VAULT_WASM));
        let factory = env.register(Factory, (vault_wasm,));
        let client = FactoryClient::new(&env, &factory);
        let salt = BytesN::from_array(&env, &[4; 32]);
        let a = client.create(
            &salt,
            &owner,
            &executor,
            &authority,
            &asset,
            &policy,
            &source,
            &policy_wasm,
            &1_000_000,
        );
        let b = client.create(
            &salt,
            &other,
            &executor,
            &authority,
            &asset,
            &policy,
            &source,
            &policy_wasm,
            &1_000_000,
        );
        assert_ne!(a, b);
        assert_eq!(VaultClient::new(&env, &a).state().owner, owner);
        assert_eq!(VaultClient::new(&env, &b).state().owner, other);
        assert!(
            client
                .try_create(
                    &salt,
                    &owner,
                    &executor,
                    &authority,
                    &asset,
                    &policy,
                    &source,
                    &policy_wasm,
                    &1_000_000
                )
                .is_err()
        );
    }
}
