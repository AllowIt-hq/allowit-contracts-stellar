const POLICY_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_policy.wasm");
use super::*;
use allowit_policy::NativePolicyClient;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::{Client as TokenClient, StellarAssetClient},
};

struct Fixture {
    env: Env,
    owner: Address,
    executor: Address,
    recipient: Address,
    vault: Address,
    asset: Address,
}
impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().with_mut(|l| l.timestamp = 86_401);
        let owner = Address::generate(&env);
        let recipient = Address::generate(&env);
        let executor = Address::generate(&env);
        let admin = Address::generate(&env);
        let asset = env.register_stellar_asset_contract_v2(admin).address();
        StellarAssetClient::new(&env, &asset).mint(&owner, &1_000_000_000);
        let policy = env.register(POLICY_WASM, ());
        let source = NativePolicyClient::new(&env, &policy).source_hash();
        let vault = env.register(
            Vault,
            (
                owner.clone(),
                executor.clone(),
                asset.clone(),
                policy,
                source,
                env.crypto()
                    .sha256(&soroban_sdk::Bytes::from_slice(&env, POLICY_WASM))
                    .to_bytes(),
                25_000_000u64,
            ),
        );
        VaultClient::new(&env, &vault).deposit(&owner, &100_000_000);
        Self {
            env,
            owner,
            executor,
            recipient,
            vault,
            asset,
        }
    }
    fn client(&self) -> VaultClient<'_> {
        VaultClient::new(&self.env, &self.vault)
    }
}
#[test]
fn custody_transfer_daily_boundary_and_atomic_denial() {
    let f = Fixture::new();
    let c = f.client();
    assert!(c.try_transfer(&f.recipient, &1, &0, &0).is_err());
    c.approve(&true, &0);
    c.transfer(&f.recipient, &20_000_000, &0, &1);
    assert_eq!(f.env.auths()[0].0, f.executor);
    let before = c.state();
    assert!(c.try_transfer(&f.recipient, &6_000_000, &1, &1).is_err());
    assert_eq!(c.state(), before);
    assert_eq!(
        TokenClient::new(&f.env, &f.asset).balance(&f.recipient),
        200_000_000
    );
    c.transfer(&f.recipient, &5_000_000, &1, &1);
    assert_eq!(c.state().spent, 25_000_000);
    assert!(c.try_transfer(&f.recipient, &1, &2, &1).is_err());
    f.env.ledger().with_mut(|l| l.timestamp = 172_800);
    c.transfer(&f.recipient, &25_000_000, &2, &1);
    assert_eq!(c.state().spent, 25_000_000);
    assert_eq!(c.state().nonce, 3);
}
#[test]
fn deposits_tuning_and_policy_switch_preserve_spending() {
    let f = Fixture::new();
    let c = f.client();
    c.approve(&true, &0);
    c.transfer(&f.recipient, &20_000_000, &0, &1);
    assert_eq!(f.env.auths()[0].0, f.executor);
    // Mint a top-up because the initial owner balance was fully deposited.
    StellarAssetClient::new(&f.env, &f.asset).mint(&f.owner, &100_000_000);
    c.deposit(&f.owner, &10_000_000);
    assert_eq!(c.state().spent, 20_000_000);
    let before = c.state();
    assert!(c.try_set_daily_limit(&50_000_001, &1).is_err());
    assert_eq!(c.state(), before);
    c.set_daily_limit(&40_000_000, &1);
    assert_eq!(c.state().spent, 20_000_000);
    assert!(c.try_transfer(&f.recipient, &1, &1, &1).is_err());
    c.transfer(&f.recipient, &20_000_000, &1, &2);
    let s = c.state();
    let policy = f.env.register(POLICY_WASM, ());
    c.set_policy(
        &policy,
        &NativePolicyClient::new(&f.env, &policy).source_hash(),
        &f.env
            .crypto()
            .sha256(&soroban_sdk::Bytes::from_slice(&f.env, POLICY_WASM))
            .to_bytes(),
        &2,
    );
    assert_eq!(c.state().spent, s.spent);
    assert_eq!(c.state().nonce, s.nonce);
    assert!(!c.state().approved);
    assert!(c.try_transfer(&f.recipient, &1, &2, &3).is_err());
}
#[test]
fn revocation_withdrawal_and_unsupported_leave_counter_intact() {
    let f = Fixture::new();
    let c = f.client();
    c.approve(&true, &0);
    c.transfer(&f.recipient, &10_000_000, &0, &1);
    c.approve(&false, &1);
    assert!(c.try_transfer(&f.recipient, &1, &1, &2).is_err());
    c.withdraw(&90_000_000);
    assert_eq!(c.balance(), 0);
    assert_eq!(c.state().spent, 10_000_000);
    assert_eq!(c.try_unsupported(&1), Err(Ok(Error::UnsupportedMethod)));
}
#[test]
fn owner_and_executor_authorization_are_required() {
    let f = Fixture::new();
    f.env.mock_auths(&[]);
    assert!(f.client().try_approve(&true, &0).is_err());
    assert!(f.client().try_withdraw(&1).is_err());
    assert_eq!(f.client().state().revision, 0);
}

#[test]
fn wrong_policy_artifact_is_rejected_without_resetting_state() {
    let f = Fixture::new();
    let c = f.client();
    let s = c.state();
    assert_eq!(
        c.try_set_policy(
            &s.policy,
            &s.policy_source,
            &BytesN::from_array(&f.env, &[0; 32]),
            &0
        ),
        Err(Ok(Error::SourceChanged))
    );
    assert_eq!(c.state(), s);
    f.env.mock_auths(&[]);
    assert!(c.try_transfer(&f.recipient, &1, &0, &0).is_err());
    assert!(c.try_deposit(&f.owner, &1).is_err());
    assert!(c.try_set_daily_limit(&1, &0).is_err());
    assert!(
        c.try_set_policy(&s.policy, &s.policy_source, &s.policy_wasm, &0)
            .is_err()
    );
}
