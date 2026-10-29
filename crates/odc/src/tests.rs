extern crate std;

use super::*;
use core::ops::Deref;
type RawClient<'a> = super::OdcClient<'a>;

use soroban_sdk::{
    IntoVal, TryIntoVal, contract, contractimpl,
    testutils::{Address as _, Ledger, MockAuth, MockAuthInvoke},
    token::StellarAssetClient,
    vec,
};

const ENGINE_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/allowit_wallet_engine.wasm");

const ODC_WASM: &[u8] = include_bytes!("../../../target/wasm32v1-none/release/allowit_odc.wasm");

#[contract]
struct Allow;
#[contractimpl]
impl Allow {
    pub fn daily_cap(env: Env, request: EngineRequest, state: EngineState) -> EngineResult {
        env.storage().instance().set(&0u32, &request);
        EngineResult {
            approval: true,
            spent: state.spent,
        }
    }
}
#[contract]
struct Deny;
#[contractimpl]
impl Deny {
    pub fn total_cap(_env: Env, _request: EngineRequest, state: EngineState) -> EngineResult {
        EngineResult {
            approval: false,
            spent: state.spent,
        }
    }
}
#[contract]
struct Trap;
#[contractimpl]
impl Trap {
    pub fn total_cap(_env: Env, _request: EngineRequest, _state: EngineState) -> EngineResult {
        panic!("malicious engine")
    }
}
#[contract]
struct Steal;
#[contractimpl]
impl Steal {
    pub fn total_cap(env: Env, request: EngineRequest, state: EngineState) -> EngineResult {
        token::Client::new(&env, &request.asset).transfer(
            &request.wallet,
            env.current_contract_address(),
            &1,
        );
        EngineResult {
            approval: true,
            spent: state.spent,
        }
    }
}

struct TestClient<'a> {
    client: RawClient<'a>,
    env: &'a Env,
    wallet: &'a Address,
}
impl<'a> TestClient<'a> {
    fn new(env: &'a Env, address: &'a Address) -> Self {
        Self {
            client: RawClient::new(env, address),
            env,
            wallet: address,
        }
    }
    fn deployment(&self, previous: u64) -> PolicyDeployment {
        let s = self.state();
        let enabled = self.env.as_contract(self.wallet, || {
            self.env.storage().instance().has(&Key::X402Config)
        });
        PolicyDeployment {
            deployment_version: previous.checked_add(1).unwrap(),
            owner: s.owner,
            agent: s.agent,
            engine: s.engine,
            grant: s.grant,
            x402_enabled: enabled,
            wasm_hash: None,
        }
    }
    fn set_grant(&self, grant: &Grant, previous: &u64) {
        self.try_set_grant(grant, previous).unwrap().unwrap();
    }
    fn try_set_grant(
        &self,
        grant: &Grant,
        previous: &u64,
    ) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>
    {
        let mut p = self.deployment(*previous);
        p.grant = grant.clone();
        p.x402_enabled = false;
        self.client.try_deploy_policy(&p)
    }
    fn set_agent(&self, agent: &Address, previous: &u64) {
        self.try_set_agent(agent, previous).unwrap().unwrap();
    }
    fn try_set_agent(
        &self,
        agent: &Address,
        previous: &u64,
    ) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>
    {
        let mut p = self.deployment(*previous);
        p.agent = agent.clone();
        p.x402_enabled = false;
        self.client.try_deploy_policy(&p)
    }
    fn set_engine(&self, engine: &Address, previous: &u64) {
        self.try_set_engine(engine, previous).unwrap().unwrap();
    }
    fn try_set_engine(
        &self,
        engine: &Address,
        previous: &u64,
    ) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>
    {
        let mut p = self.deployment(*previous);
        p.engine = engine.clone();
        self.client.try_deploy_policy(&p)
    }
    fn set_paused(&self, paused: &bool, previous: &u64) {
        self.client
            .set_pause(paused, &previous.checked_add(1).unwrap());
    }
    fn try_set_paused(
        &self,
        paused: &bool,
        previous: &u64,
    ) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>
    {
        self.client
            .try_set_pause(paused, &previous.checked_add(1).unwrap())
    }
    fn set_x402_enabled(&self, enabled: bool, previous: &u64) {
        let mut p = self.deployment(*previous);
        p.x402_enabled = enabled;
        self.client.deploy_policy(&p);
    }
    fn try_transfer_owner(
        &self,
        owner: &Address,
        previous: &u64,
    ) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>
    {
        let mut p = self.deployment(*previous);
        p.owner = owner.clone();
        self.client.try_deploy_policy(&p)
    }
    fn upgrade(&self, hash: &BytesN<32>, previous: &u64) {
        self.try_upgrade(hash, previous).unwrap().unwrap();
    }
    fn try_upgrade(
        &self,
        hash: &BytesN<32>,
        previous: &u64,
    ) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>
    {
        let mut p = self.deployment(*previous);
        p.wasm_hash = Some(hash.clone());
        self.client.try_deploy_policy(&p)
    }
    fn recover(&self, recipient: &Address, amount: &i128, _previous: &u64) {
        self.client.recover(recipient, amount);
    }
    fn try_recover(
        &self,
        recipient: &Address,
        amount: &i128,
        _previous: &u64,
    ) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>
    {
        self.client.try_recover(recipient, amount)
    }
    fn envelope(&self, request: &TransferRequest) -> ExecutionRequest {
        let installed = self.client.policy_binding();
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&request.nonce.checked_add(1).unwrap().to_be_bytes());
        ExecutionRequest {
            policy_instance: installed.policy_instance,
            operation_id: BytesN::from_array(self.env, &id),
            nonce: request.nonce,
            deployment_version: request.deployment_version,
            expires_at: request.expires_at,
            invocation: allowit_wallet_protocol::PolicyInvocation {
                module_digest: installed.module_digest,
                entrypoint: installed.entrypoint,
                argument_schema_digest: installed.argument_schema_digest,
                arguments: Sep41TransferArgs {
                    token: self.client.state().asset,
                    from: self.wallet.clone(),
                    to: request.recipient.clone(),
                    amount: request.amount,
                }
                .to_xdr(self.env),
            },
        }
    }
    fn transfer(&self, request: &TransferRequest) {
        self.client.execute(&self.envelope(request));
    }
    fn try_transfer(
        &self,
        request: &TransferRequest,
    ) -> Result<
        Result<TransferReceipt, soroban_sdk::ConversionError>,
        Result<Error, soroban_sdk::InvokeError>,
    > {
        self.client.try_execute(&self.envelope(request))
    }
}
impl<'a> Deref for TestClient<'a> {
    type Target = RawClient<'a>;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

struct Fixture {
    env: Env,
    owner: Address,
    agent: Address,
    recipient: Address,
    asset: Address,
    odc: Address,
    engine: Address,
}
impl Fixture {
    fn new(compiled: bool) -> Self {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.mock_all_auths_allowing_non_root_auth();
        env.ledger().with_mut(|l| l.timestamp = DAY + 10);
        let owner = Address::generate(&env);
        let agent = Address::generate(&env);
        let recipient = Address::generate(&env);
        let issuer = Address::generate(&env);
        let sac = env.register_stellar_asset_contract_v2(issuer);
        sac.issuer()
            .set_flag(soroban_sdk::testutils::IssuerFlags::RevocableFlag);
        let asset = sac.address();
        let engine = if compiled {
            env.register(ENGINE_WASM, ())
        } else {
            env.register(Allow, ())
        };
        let grant = Grant::new(&env);
        let args = (
            owner.clone(),
            agent.clone(),
            engine.clone(),
            asset.clone(),
            grant,
            BytesN::from_array(&env, &[1; 32]),
        );
        let odc = if compiled {
            env.register(ODC_WASM, args)
        } else {
            env.register(Odc, args)
        };
        env.mock_all_auths();
        StellarAssetClient::new(&env, &asset).mint(&odc, &1_000);
        Self {
            env,
            owner,
            agent,
            recipient,
            asset,
            odc,
            engine,
        }
    }
    fn client(&self) -> TestClient<'_> {
        TestClient::new(&self.env, &self.odc)
    }
    fn request(&self, amount: i128) -> TransferRequest {
        let state = self.client().state();
        TransferRequest {
            recipient: self.recipient.clone(),
            amount,
            nonce: state.nonce,
            deployment_version: state.deployment_version,
            expires_at: self.env.ledger().timestamp() + 100,
        }
    }
    fn balance(&self, address: &Address) -> i128 {
        token::Client::new(&self.env, &self.asset).balance(address)
    }
}

const STATE_POLICY_WASM: &[u8] =
    include_bytes!("../../../target/test-fixtures/odc_state_policy.wasm");
const LOCAL_POLICY_WASM: &[u8] =
    include_bytes!("../../../target/test-fixtures/odc_local_state_policy.wasm");
impl Fixture {
    fn policy(wasm: &[u8]) -> Self {
        let mut f = Self::new(true);
        let mut grant = Grant::new(&f.env);
        for (name, value) in [
            ("daily_limit", 150u64),
            ("total_limit", 250),
            ("max_calls", 3),
            ("per_transfer", 1),
        ] {
            grant.set(String::from_str(&f.env, name), value.into_val(&f.env));
        }
        grant.set(
            String::from_str(&f.env, "arbitrary_bytes"),
            Bytes::from_slice(&f.env, &[1, 2, 3]).into_val(&f.env),
        );
        f.env.mock_all_auths_allowing_non_root_auth();
        f.odc = f.env.register(
            wasm,
            (
                f.owner.clone(),
                f.agent.clone(),
                f.engine.clone(),
                f.asset.clone(),
                grant,
                BytesN::from_array(&f.env, &[2; 32]),
            ),
        );
        f.env.mock_all_auths();
        StellarAssetClient::new(&f.env, &f.asset).mint(&f.odc, &1000);
        f
    }
    fn spent(&self) -> allowit_wallet_protocol::Spent {
        self.client()
            .policy_spent()
            .unwrap_or_else(|| Grant::new(&self.env))
    }
    fn used(&self, name: &str) -> i128 {
        let raw = self.spent().get(String::from_str(&self.env, name)).unwrap();
        i128::try_from_val(&self.env, &raw)
            .unwrap_or_else(|_| i128::from(u64::try_from_val(&self.env, &raw).unwrap()))
    }
    fn seed_spent(&self, map: &allowit_wallet_protocol::Spent) {
        self.env.as_contract(&self.odc, || {
            let instance = self
                .env
                .storage()
                .instance()
                .get(&Key::PolicyInstance)
                .unwrap();
            let storage = NativePolicyStorage {
                env: &self.env,
                policy_instance: instance,
            };
            let before = storage.load().unwrap();
            storage.commit(&before, map);
        });
    }
}

#[test]
fn unrestricted_authored_policy_preserves_native_safety_and_replay() {
    let f = Fixture::new(false);
    let c = f.client();
    let mut grant = Grant::new(&f.env);
    grant.set(
        String::from_str(&f.env, "per_transfer"),
        1u64.into_val(&f.env),
    );
    c.set_grant(&grant, &0);
    let first = f.request(101);
    c.transfer(&first); // A named value is not an automatic kernel spending limit.
    assert!(c.policy_spent().is_none());
    assert_eq!(c.try_transfer(&first), Err(Ok(Error::Replay)));
    let before = c.state();
    let mut expired = f.request(1);
    expired.expires_at = f.env.ledger().timestamp();
    assert_eq!(c.try_transfer(&expired), Err(Ok(Error::Expired)));
    let mut self_payment = f.request(1);
    self_payment.recipient = f.odc.clone();
    assert_eq!(
        c.try_transfer(&self_payment),
        Err(Ok(Error::InvalidRecipient))
    );
    assert_eq!(c.try_transfer(&f.request(0)), Err(Ok(Error::InvalidAmount)));
    let mut stale = f.request(1);
    stale.nonce += 1;
    assert_eq!(c.try_transfer(&stale), Err(Ok(Error::StaleRequest)));
    assert_eq!(c.state(), before);
}

#[test]
fn owner_controls_require_owner_not_agent_and_deployment_version_is_exact() {
    let f = Fixture::new(false);
    let c = f.client();
    let outsider = Address::generate(&f.env);
    f.env.mock_auths(&[]);
    assert!(c.try_set_paused(&true, &0).is_err());
    assert!(c.try_set_agent(&outsider, &0).is_err());
    assert!(c.try_set_engine(&outsider, &0).is_err());
    assert!(c.try_set_grant(&c.state().grant, &0).is_err());
    assert!(c.try_recover(&outsider, &1, &0).is_err());
    assert!(c.try_transfer_owner(&outsider, &0).is_err());
    assert!(
        c.try_upgrade(&BytesN::from_array(&f.env, &[0; 32]), &0)
            .is_err()
    );
    assert!(c.try_transfer(&f.request(1)).is_err());
    f.env.mock_auths(&[MockAuth {
        address: &f.agent,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "set_pause",
            args: (true, 1u64).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    assert!(c.try_set_paused(&true, &0).is_err());
    f.env.mock_auths(&[MockAuth {
        address: &f.owner,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "set_pause",
            args: (true, 1u64).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    c.set_paused(&true, &0);
    f.env.mock_all_auths();
    assert_eq!(c.try_set_paused(&false, &0), Err(Ok(Error::StaleRequest)));
    assert_eq!(c.state().deployment_version, 1);
    assert_eq!(c.try_unsupported(), Err(Ok(Error::UnsupportedOperation)));
}

#[test]
fn actual_sac_failure_rolls_back_local_accounting() {
    let f = Fixture::new(false);
    let c = f.client();
    StellarAssetClient::new(&f.env, &f.asset).set_authorized(&f.odc, &false);
    let before = c.state();
    assert!(c.try_transfer(&f.request(1)).is_err());
    assert_eq!(c.state(), before);
    assert_eq!(f.balance(&f.recipient), 0);
}

#[test]
fn owner_handoff_requires_candidate_acceptance_and_invalidates_old_requests() {
    let f = Fixture::new(false);
    let c = f.client();
    let candidate = Address::generate(&f.env);
    let mut deployment = c.deployment(0);
    deployment.owner = candidate.clone();
    let args: soroban_sdk::Vec<soroban_sdk::Val> = (deployment.clone(),).into_val(&f.env);
    f.env.mock_auths(&[MockAuth {
        address: &f.owner,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "deploy_policy",
            args: args.clone(),
            sub_invokes: &[],
        },
    }]);
    assert!(c.try_transfer_owner(&candidate, &0).is_err());
    assert_eq!(c.state().owner, f.owner);
    let old = f.request(1);
    f.env.mock_auths(&[
        MockAuth {
            address: &f.owner,
            invoke: &MockAuthInvoke {
                contract: &f.odc,
                fn_name: "deploy_policy",
                args: args.clone(),
                sub_invokes: &[],
            },
        },
        MockAuth {
            address: &candidate,
            invoke: &MockAuthInvoke {
                contract: &f.odc,
                fn_name: "deploy_policy",
                args,
                sub_invokes: &[],
            },
        },
    ]);
    c.deploy_policy(&deployment);
    f.env.mock_all_auths();
    assert_eq!(c.try_transfer(&old), Err(Ok(Error::StaleRequest)));
}

#[test]
fn raw_contract_account_auth_is_not_an_alternative_spending_path() {
    let f = Fixture::new(true);
    let req = f.request(1);
    f.env.mock_auths(&[MockAuth {
        address: &f.agent,
        invoke: &MockAuthInvoke {
            contract: &f.asset,
            fn_name: "transfer",
            args: (f.odc.clone(), f.recipient.clone(), 1i128).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    let before = f.client().state();
    // The optional hook is disabled. An agent credential is not
    // authorization for the ODC address at the SAC's direct entrypoint.
    assert!(
        token::Client::new(&f.env, &f.asset)
            .try_transfer(&f.odc, &f.recipient, &1)
            .is_err()
    );
    assert_eq!(f.client().state(), before);
    assert_eq!(f.balance(&f.recipient), 0);
    assert_eq!(req.nonce, 0);
}

#[test]
fn grant_custom_asset_key_cannot_change_custody_asset_and_failed_upgrade_rolls_back() {
    let f = Fixture::new(false);
    let c = f.client();
    let mut grant = c.state().grant;
    grant.set(
        String::from_str(&f.env, "asset"),
        Address::generate(&f.env).into_val(&f.env),
    );
    c.set_grant(&grant, &0);
    let before = c.state();
    assert_eq!(before.asset, f.asset);
    assert!(
        c.try_upgrade(&BytesN::from_array(&f.env, &[0; 32]), &1)
            .is_err()
    );
    assert_eq!(c.state(), before);
}

#[test]
fn every_admin_role_collision_is_rejected_without_state_change() {
    let f = Fixture::new(false);
    let c = f.client();
    let before = c.state();
    for engine in [&f.owner, &f.agent, &f.odc] {
        assert_eq!(c.try_set_engine(engine, &0), Err(Ok(Error::InvalidActor)));
    }
    for agent in [&f.owner, &f.engine, &f.odc] {
        assert_eq!(c.try_set_agent(agent, &0), Err(Ok(Error::InvalidActor)));
    }
    for owner in [&f.agent, &f.engine, &f.odc] {
        assert_eq!(
            c.try_transfer_owner(owner, &0),
            Err(Ok(Error::InvalidActor))
        );
    }
    f.env.as_contract(&f.odc, || {
        for (owner, agent, engine) in [
            (&f.owner, &f.owner, &f.engine),
            (&f.owner, &f.agent, &f.owner),
            (&f.owner, &f.agent, &f.agent),
            (&f.odc, &f.agent, &f.engine),
            (&f.owner, &f.odc, &f.engine),
            (&f.owner, &f.agent, &f.odc),
        ] {
            assert_eq!(
                validate_roles(&f.env, owner, agent, engine),
                Err(Error::InvalidActor)
            );
        }
    });
    assert_eq!(c.state(), before);
}

#[test]
fn compiled_engine_and_odc_transfer_fit_default_resource_budget() {
    let f = Fixture::new(true);
    let request = f.request(10);
    let mut budget = f.env.cost_estimate().budget();
    budget.reset_default();
    f.client().transfer(&request);
    let cpu = budget.cpu_instruction_cost();
    let memory = budget.memory_bytes_cost();
    std::println!("compiled_odc_plus_engine_transfer_cpu={cpu} memory_bytes={memory}");
    assert!(cpu <= 100_000_000);
    assert!(memory <= 40 * 1024 * 1024);
    assert_eq!(f.balance(&f.recipient), 10);
}

#[test]
fn compiled_transfer_requires_exact_agent_auth_without_subinvocations() {
    use soroban_sdk::testutils::{AuthorizedFunction, AuthorizedInvocation};
    let f = Fixture::new(true);
    let request = f.request(10);
    let args: soroban_sdk::Vec<soroban_sdk::Val> =
        (f.client().envelope(&request),).into_val(&f.env);
    f.env.mock_auths(&[MockAuth {
        address: &f.agent,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "execute",
            args: args.clone(),
            sub_invokes: &[],
        },
    }]);
    f.client().transfer(&request);
    assert_eq!(
        f.env.auths(),
        std::vec![(
            f.agent.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    f.odc.clone(),
                    soroban_sdk::Symbol::new(&f.env, "execute"),
                    args,
                )),
                sub_invocations: std::vec![],
            },
        )]
    );
    assert_eq!(f.balance(&f.recipient), 10);
    assert!(f.client().policy_spent().is_none());
}

#[test]
fn execute_requires_installed_module_schema_entrypoint_and_exact_arguments() {
    let f = Fixture::new(true);
    let client = f.client();
    let original = client.envelope(&f.request(10));
    let before = client.state();
    let mut invalid = std::vec::Vec::new();
    let zero = BytesN::from_array(&f.env, &[0; 32]);
    let mut changed = original.clone();
    changed.policy_instance = zero.clone();
    invalid.push(changed);
    let mut changed = original.clone();
    changed.operation_id = zero.clone();
    invalid.push(changed);
    let mut changed = original.clone();
    changed.invocation.module_digest = zero.clone();
    invalid.push(changed);
    let mut changed = original.clone();
    changed.invocation.argument_schema_digest = zero;
    invalid.push(changed);
    let mut changed = original.clone();
    changed.invocation.entrypoint = Symbol::new(&f.env, "transfer");
    invalid.push(changed);
    let mut changed = original.clone();
    changed.invocation.arguments.push_back(0);
    invalid.push(changed);
    let mut changed = original.clone();
    changed.invocation.arguments = soroban_sdk::Bytes::from_array(&f.env, &[0; 1025]);
    invalid.push(changed);
    for (token, from) in [
        (Address::generate(&f.env), f.odc.clone()),
        (f.asset.clone(), Address::generate(&f.env)),
    ] {
        let mut changed = original.clone();
        changed.invocation.arguments = Sep41TransferArgs {
            token,
            from,
            to: f.recipient.clone(),
            amount: 10,
        }
        .to_xdr(&f.env);
        invalid.push(changed);
    }
    for (index, request) in invalid.into_iter().enumerate() {
        if index == 5 {
            // Invalid XDR is rejected by the native host before conversion can return.
            assert!(client.try_execute(&request).is_err());
        } else {
            assert_eq!(
                client.try_execute(&request),
                Err(Ok(Error::InvalidInvocation))
            );
        }
        assert_eq!(client.state(), before);
        assert_eq!(f.balance(&f.odc), 1000);
        assert_eq!(f.balance(&f.recipient), 0);
    }
    let receipt = client.execute(&original);
    assert_eq!(receipt.operation_id, original.operation_id);
    assert_eq!(receipt.token, f.asset);
    assert_eq!(receipt.from, f.odc);
    assert_eq!(receipt.to, f.recipient);
    assert_eq!(receipt.amount, 10);
    assert_eq!(receipt.nonce, 0);
}

#[test]
fn operation_id_is_single_use_across_fresh_nonces_and_configuration_changes() {
    let f = Fixture::new(true);
    let client = f.client();
    let first = client.envelope(&f.request(10));
    client.execute(&first);
    let grant = client.state().grant;
    client.set_grant(&grant, &0);
    let mut repeated = client.envelope(&f.request(10));
    repeated.operation_id = first.operation_id;
    let before = client.state();
    assert_eq!(client.try_execute(&repeated), Err(Ok(Error::Replay)));
    assert_eq!(client.state(), before);
    assert_eq!(f.balance(&f.recipient), 10);
}

#[test]
fn unbound_upgrade_state_cannot_execute_but_owner_recovery_remains_independent() {
    let f = Fixture::new(true);
    let client = f.client();
    let request = client.envelope(&f.request(10));
    // A previous compatible State record has no new installation identity.
    // Never guess that identity or reset the old counters on upgrade.
    f.env.as_contract(&f.odc, || {
        f.env.storage().instance().remove(&Key::PolicyInstance);
    });
    assert_eq!(client.try_execute(&request), Err(Ok(Error::InvalidState)));
    let before = client.state();
    client.recover(&f.owner, &10, &before.deployment_version);
    let after = client.state();
    assert_eq!(after.nonce, before.nonce);
    assert_eq!(f.balance(&f.owner), 10);
}

#[test]
fn old_transfer_entrypoint_is_not_exported() {
    let f = Fixture::new(true);
    let result = f.env.try_invoke_contract::<(), Error>(
        &f.odc,
        &Symbol::new(&f.env, "transfer"),
        vec![&f.env, f.request(1).into_val(&f.env)],
    );
    assert!(result.is_err());
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.balance(&f.odc), 1000);
}

#[test]
fn a_custom_expiry_key_does_not_add_a_mandatory_kernel_guard() {
    let f = Fixture::new(false);
    let c = f.client();
    let mut grant = c.state().grant;
    grant.set(
        String::from_str(&f.env, "expires_at"),
        1u64.into_val(&f.env),
    );
    c.set_grant(&grant, &0);
    c.transfer(&f.request(1));
    assert_eq!(c.state().nonce, 1);
}

#[test]
fn compiled_authored_private_policy_rejects_effect_allowed_by_grant_and_engine() {
    const POLICY_WASM: &[u8] =
        include_bytes!("../../../target/test-fixtures/odc_recipient_policy.wasm");
    const POLICY_SOURCE: &[u8] = include_bytes!("../policy/recipient-policy.rs");
    let f = Fixture::new(true);
    let env = &f.env;
    let allowed = Address::from_str(
        env,
        "CBNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVXQOK",
    );
    let mut grant = f.client().state().grant;
    grant.set(
        String::from_str(env, "uninterpreted_recipient"),
        allowed.clone().into_val(env),
    );
    env.mock_all_auths_allowing_non_root_auth();
    let wallet = env.register(
        POLICY_WASM,
        (
            f.owner.clone(),
            f.agent.clone(),
            f.engine.clone(),
            f.asset.clone(),
            grant,
            BytesN::from_array(env, &[9; 32]),
        ),
    );
    env.mock_all_auths();
    StellarAssetClient::new(env, &f.asset).mint(&wallet, &1000);
    let client = TestClient::new(env, &wallet);
    let binding = client.policy_binding();
    assert_eq!(
        binding.source_digest,
        env.crypto()
            .sha256(&soroban_sdk::Bytes::from_slice(env, POLICY_SOURCE))
            .to_bytes()
    );
    assert_eq!(
        binding.module_digest,
        env.crypto()
            .sha256(&soroban_sdk::Bytes::from_slice(env, POLICY_WASM))
            .to_bytes()
    );
    let mut request = TransferRequest {
        recipient: f.recipient.clone(),
        amount: 10,
        nonce: 0,
        deployment_version: 0,
        expires_at: env.ledger().timestamp() + 100,
    };
    let before = client.state();
    // The owner envelope and allow-all engine permit this recipient, but the
    // statically compiled source's private _execute guard rejects it.
    assert_eq!(client.try_transfer(&request), Err(Ok(Error::PolicyDenied)));
    assert_eq!(client.state(), before);
    assert_eq!(f.balance(&wallet), 1000);
    assert_eq!(f.balance(&f.recipient), 0);
    request.recipient = allowed.clone();
    client.transfer(&request);
    assert_eq!(f.balance(&allowed), 10);
    assert!(client.policy_spent().is_none());
    assert_eq!(client.state().nonce, 1);
}

#[test]
fn native_xlm_label_uses_network_asset_identity_not_a_token_symbol_alias() {
    use soroban_sdk::xdr::{self, WriteXdr};
    let (native_env, _, issuer) = native_env();
    let env = &native_env;
    let native = env
        .deployer()
        .with_stellar_asset(soroban_sdk::Bytes::from_array(env, &[0; 4]))
        .deploy();
    assert_eq!(
        token::Client::new(env, &native).symbol(),
        soroban_sdk::String::from_str(env, "native")
    );
    assert_eq!(
        policy_token(env, &native),
        soroban_sdk::String::from_str(env, "XLM")
    );
    let mut code = [0u8; 12];
    code[..6].copy_from_slice(b"native");
    let issued = xdr::Asset::CreditAlphanum12(xdr::AlphaNum12 {
        asset_code: xdr::AssetCode12(code),
        issuer,
    });
    let bytes = issued.to_xdr(xdr::Limits::none()).unwrap();
    let issued_contract = env
        .deployer()
        .with_stellar_asset(soroban_sdk::Bytes::from_slice(env, &bytes))
        .deploy();
    assert_ne!(issued_contract, native);
    assert_eq!(
        token::Client::new(env, &issued_contract).symbol(),
        soroban_sdk::String::from_str(env, "native")
    );
    assert_eq!(
        policy_token(env, &issued_contract),
        soroban_sdk::String::from_str(env, "native")
    );
}

#[test]
fn compiled_same_xlm_policy_executes_native_sac_and_rejects_issued_native_alias() {
    use soroban_sdk::xdr::{self, WriteXdr};
    const XLM_POLICY_WASM: &[u8] =
        include_bytes!("../../../target/test-fixtures/odc_xlm_policy.wasm");
    let (env, bank, issuer) = native_env();
    env.ledger().with_mut(|l| l.timestamp = DAY + 10);
    env.mock_all_auths_allowing_non_root_auth();
    let native = env
        .deployer()
        .with_stellar_asset(Bytes::from_array(&env, &[0; 4]))
        .deploy();
    let engine = env.register(ENGINE_WASM, ());
    let owner = Address::generate(&env);
    let agent = Address::generate(&env);
    let recipient = Address::from_str(
        &env,
        "CBNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVWW23LNNVXQOK",
    );
    let grant = Grant::new(&env);
    let wallet = env.register(
        XLM_POLICY_WASM,
        (
            owner.clone(),
            agent.clone(),
            engine.clone(),
            native.clone(),
            grant.clone(),
            BytesN::from_array(&env, &[61; 32]),
        ),
    );
    env.mock_all_auths();
    token::Client::new(&env, &native).transfer(&bank, &wallet, &1000);
    let client = TestClient::new(&env, &wallet);
    let request = TransferRequest {
        recipient: recipient.clone(),
        amount: 10,
        nonce: 0,
        deployment_version: 0,
        expires_at: DAY + 100,
    };
    client.transfer(&request);
    assert_eq!(token::Client::new(&env, &native).balance(&wallet), 990);
    assert_eq!(token::Client::new(&env, &native).balance(&recipient), 10);
    assert!(client.policy_spent().is_none());
    assert_eq!(
        client.policy_binding().source_digest,
        env.crypto()
            .sha256(&Bytes::from_slice(
                &env,
                include_bytes!("../policy/xlm-policy.rs")
            ))
            .to_bytes()
    );

    let mut code = [0u8; 12];
    code[..6].copy_from_slice(b"native");
    let issued = xdr::Asset::CreditAlphanum12(xdr::AlphaNum12 {
        asset_code: xdr::AssetCode12(code),
        issuer,
    });
    let issued = env
        .deployer()
        .with_stellar_asset(Bytes::from_slice(
            &env,
            &issued.to_xdr(xdr::Limits::none()).unwrap(),
        ))
        .deploy();
    let issued_grant = grant;
    env.mock_all_auths_allowing_non_root_auth();
    let issued_wallet = env.register(
        XLM_POLICY_WASM,
        (
            owner,
            agent,
            engine,
            issued.clone(),
            issued_grant,
            BytesN::from_array(&env, &[62; 32]),
        ),
    );
    env.mock_all_auths();
    StellarAssetClient::new(&env, &issued).mint(&issued_wallet, &1000);
    let issued_client = TestClient::new(&env, &issued_wallet);
    assert_eq!(
        issued_client.try_transfer(&request),
        Err(Ok(Error::PolicyDenied))
    );
    assert!(issued_client.policy_spent().is_none());
    assert_eq!(
        token::Client::new(&env, &issued).balance(&issued_wallet),
        1000
    );
    assert_eq!(token::Client::new(&env, &issued).balance(&recipient), 0);
}

#[test]
fn x402_rejects_mutation_context_and_revocation() {
    let (f, key) = x402_setup_compiled(false);
    let payload = BytesN::from_array(&f.env, &[42; 32]);
    let execution = f.client().envelope(&f.request(50));
    let sig = x402_signed(&f, &key, execution.clone(), &payload);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                sig.clone().into_val(&f.env),
                &x402_context(&f, 51)
            )
            .is_err()
    );
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                sig.clone().into_val(&f.env),
                &vec![&f.env]
            )
            .is_err()
    );
    let altered = BytesN::from_array(&f.env, &[43; 32]);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &altered,
                sig.clone().into_val(&f.env),
                &x402_context(&f, 50)
            )
            .is_err()
    );
    let c = TestClient::new(&f.env, &f.odc);
    c.set_grant(&c.state().grant, &c.state().deployment_version);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                sig.into_val(&f.env),
                &x402_context(&f, 50)
            )
            .is_err()
    );
    assert!(c.policy_spent().is_none());
}

#[test]
fn x402_context_and_owner_revocation_matrix() {
    let (f, key) = x402_setup_compiled(false);
    let payload = BytesN::from_array(&f.env, &[42; 32]);
    let valid = f.client().envelope(&f.request(50));
    let signature = x402_signed(&f, &key, valid.clone(), &payload);
    let Context::Contract(context) = x402_context(&f, 50).get(0).unwrap() else {
        panic!()
    };
    let mut contexts = std::vec::Vec::new();
    let mut bad = context.clone();
    bad.contract = f.engine.clone();
    contexts.push(vec![&f.env, Context::Contract(bad)]);
    let mut bad = context.clone();
    bad.fn_name = Symbol::new(&f.env, "approve");
    contexts.push(vec![&f.env, Context::Contract(bad)]);
    let mut bad = context.clone();
    bad.args.pop_back();
    contexts.push(vec![&f.env, Context::Contract(bad)]);
    let mut bad = context.clone();
    bad.args.set(0, f.owner.clone().into_val(&f.env));
    contexts.push(vec![&f.env, Context::Contract(bad)]);
    contexts.push(vec![
        &f.env,
        Context::Contract(context.clone()),
        Context::Contract(context),
    ]);
    for context in contexts {
        assert!(
            f.env
                .try_invoke_contract_check_auth::<Error>(
                    &f.odc,
                    &payload,
                    signature.clone().into_val(&f.env),
                    &context
                )
                .is_err()
        );
    }
    let mut changed_signature = signature.clone();
    changed_signature.execution.nonce += 1;
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                changed_signature.into_val(&f.env),
                &x402_context(&f, 50)
            )
            .is_err()
    );
    let c = TestClient::new(&f.env, &f.odc);
    c.set_x402_enabled(false, &c.state().deployment_version);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                signature.clone().into_val(&f.env),
                &x402_context(&f, 50)
            )
            .is_err()
    );
    c.set_x402_enabled(true, &c.state().deployment_version);
    c.set_agent(&c.state().agent, &c.state().deployment_version);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                signature.into_val(&f.env),
                &x402_context(&f, 50)
            )
            .is_err()
    );
    assert!(c.policy_spent().is_none());
}

#[test]
fn unknown_contract_release_and_old_state_format_reject() {
    let f = Fixture::new(false);
    let mut state = f.client().state();
    state.contract_version = 2;
    f.env
        .as_contract(&f.odc, || f.env.storage().instance().set(&0u32, &state));
    assert_eq!(f.client().try_state(), Err(Ok(Error::InvalidState)));
    let raw: soroban_sdk::Val = state.into_val(&f.env);
    let mut fields =
        soroban_sdk::Map::<Symbol, soroban_sdk::Val>::try_from_val(&f.env, &raw).unwrap();
    fields.remove(Symbol::new(&f.env, "contract_version"));
    fields.set(Symbol::new(&f.env, "version"), 1u32.into_val(&f.env));
    f.env
        .as_contract(&f.odc, || f.env.storage().instance().set(&0u32, &fields));
    assert_eq!(f.client().try_state(), Err(Ok(Error::InvalidState)));
}

#[test]
fn full_deployment_requires_exact_fields_and_explicit_x402_choice() {
    let (f, _) = x402_setup_compiled(false);
    let c = f.client();
    let mut policy = c.deployment(c.state().deployment_version);
    policy
        .grant
        .set(String::from_str(&f.env, "custom"), true.into_val(&f.env));
    assert!(policy.x402_enabled);
    c.deploy_policy(&policy);
    let before = c.state();
    let raw: soroban_sdk::Val = policy.clone().into_val(&f.env);
    let mut malformed =
        soroban_sdk::Map::<Symbol, soroban_sdk::Val>::try_from_val(&f.env, &raw).unwrap();
    malformed.remove(Symbol::new(&f.env, "grant"));
    assert!(
        f.env
            .try_invoke_contract::<(), Error>(
                &f.odc,
                &Symbol::new(&f.env, "deploy_policy"),
                vec![&f.env, malformed.into_val(&f.env)]
            )
            .is_err()
    );
    assert_eq!(c.state(), before);
    policy.deployment_version += 1;
    policy.x402_enabled = false;
    c.deploy_policy(&policy);
    assert!(
        f.env
            .as_contract(&f.odc, || !f.env.storage().instance().has(&Key::X402Config))
    );
}

#[test]
fn derived_x402_cache_rejects_wrong_agent_and_extra_key() {
    for compiled in [false, true] {
        let (f, _) = x402_setup_compiled(compiled);
        let before = f.client().state();
        f.env.as_contract(&f.odc, || {
            let raw: soroban_sdk::Val = f.env.storage().instance().get(&Key::X402Config).unwrap();
            let mut fields =
                soroban_sdk::Map::<Symbol, soroban_sdk::Val>::try_from_val(&f.env, &raw).unwrap();
            fields.set(
                Symbol::new(&f.env, "public_key"),
                BytesN::from_array(&f.env, &[99; 32]).into_val(&f.env),
            );
            f.env.storage().instance().set(&Key::X402Config, &fields);
            assert!(matches!(
                x402_config(&f.env, &before.agent),
                Err(Error::InvalidState)
            ));
            fields.remove(Symbol::new(&f.env, "public_key"));
            fields.set(
                Symbol::new(&f.env, "agent"),
                f.owner.clone().into_val(&f.env),
            );
            f.env.storage().instance().set(&Key::X402Config, &fields);
            assert!(matches!(
                x402_config(&f.env, &before.agent),
                Err(Error::InvalidActor)
            ));
        });
        assert_eq!(f.client().state(), before);
    }
}

#[test]
fn x402_enable_requires_explicit_owner_opt_in_and_a_g_agent() {
    let f = Fixture::new(false); // The generated contract-address agent is unsupported for x402.
    let c = f.client();
    let mut deployment = c.deployment(0);
    deployment.x402_enabled = true;
    assert_eq!(
        c.try_deploy_policy(&deployment),
        Err(Ok(Error::InvalidActor))
    );
    assert_eq!(c.state().deployment_version, 0);
    assert!(
        f.env
            .as_contract(&f.odc, || !f.env.storage().instance().has(&Key::X402Config))
    );
    assert_eq!(c.policy_binding().contract_version, 1);
    assert_eq!(c.state().contract_version, 1);
}

fn native_env() -> (Env, Address, soroban_sdk::xdr::AccountId) {
    use soroban_sdk::{TryFromVal, xdr};
    let initial = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256([87; 32])));
    let key = xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: id.clone(),
    });
    let entry = xdr::LedgerEntry {
        last_modified_ledger_seq: 0,
        data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
            account_id: id.clone(),
            balance: 1_000_000_000,
            seq_num: xdr::SequenceNumber(1),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: Default::default(),
            thresholds: xdr::Thresholds([1, 0, 0, 0]),
            signers: Default::default(),
            ext: xdr::AccountEntryExt::V0,
        }),
        ext: xdr::LedgerEntryExt::V0,
    };
    let mut snapshot = initial.to_ledger_snapshot();
    snapshot.ledger_entries.push((
        std::boxed::Box::new(key),
        (std::boxed::Box::new(entry), None),
    ));
    let mut env = Env::from_ledger_snapshot(snapshot);
    env.set_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let address = Address::try_from_val(&env, &xdr::ScAddress::Account(id.clone())).unwrap();
    (env, address, id)
}

fn x402_signed(
    f: &Fixture,
    key: &ed25519_dalek::SigningKey,
    execution: ExecutionRequest,
    payload: &BytesN<32>,
) -> X402Authorization {
    use ed25519_dalek::Signer;
    let digest = f.env.crypto().sha256(
        &(
            Symbol::new(&f.env, "allowit_x402_v1"),
            payload.clone(),
            execution.clone(),
        )
            .to_xdr(&f.env),
    );
    X402Authorization {
        execution,
        signature: BytesN::from_array(&f.env, &key.sign(&digest.to_array()).to_bytes()),
    }
}

fn x402_context(f: &Fixture, amount: i128) -> Vec<Context> {
    vec![
        &f.env,
        Context::Contract(soroban_sdk::auth::ContractContext {
            contract: f.asset.clone(),
            fn_name: Symbol::new(&f.env, "transfer"),
            args: (f.odc.clone(), f.recipient.clone(), amount).into_val(&f.env),
        }),
    ]
}

fn x402_host_entry(
    f: &Fixture,
    key: &ed25519_dalek::SigningKey,
    amount: i128,
    nonce: i64,
) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
    use soroban_sdk::xdr::{self, WriteXdr};
    let invocation: xdr::SorobanAuthorizedInvocation = (&MockAuthInvoke {
        contract: &f.asset,
        fn_name: "transfer",
        args: (f.odc.clone(), f.recipient.clone(), amount).into_val(&f.env),
        sub_invokes: &[],
    })
        .into();
    let preimage =
        xdr::HashIdPreimage::SorobanAuthorization(xdr::HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(f.env.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger: 100,
            invocation: invocation.clone(),
        });
    let payload = f
        .env
        .crypto()
        .sha256(&Bytes::from_slice(
            &f.env,
            &preimage.to_xdr(xdr::Limits::none()).unwrap(),
        ))
        .to_bytes();
    let authorization = x402_signed(f, key, f.client().envelope(&f.request(amount)), &payload);
    let signature_val: soroban_sdk::Val = authorization.into_val(&f.env);
    xdr::SorobanAuthorizationEntry {
        credentials: xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
            address: (&f.odc).into(),
            nonce,
            signature_expiration_ledger: 100,
            signature: signature_val.try_into_val(&f.env).unwrap(),
        }),
        root_invocation: invocation,
    }
}

fn x402_setup_compiled(compiled: bool) -> (Fixture, ed25519_dalek::SigningKey) {
    x402_configure(Fixture::new(compiled))
}
fn x402_configure(f: Fixture) -> (Fixture, ed25519_dalek::SigningKey) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let pubkey = BytesN::from_array(&f.env, &key.verifying_key().to_bytes());
    let mut encoded = Bytes::from_slice(&f.env, &[0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0]);
    encoded.append(&pubkey.clone().into());
    let agent = Address::from_xdr(&f.env, &encoded).unwrap();
    let c = TestClient::new(&f.env, &f.odc);
    c.set_agent(&agent, &c.state().deployment_version);
    c.set_x402_enabled(true, &c.state().deployment_version);
    (f, key)
}

#[contract]
pub struct OdcConstructorDeployer;
#[contractimpl]
impl OdcConstructorDeployer {
    pub fn deploy_odc(
        env: Env,
        wasm: BytesN<32>,
        owner: Address,
        agent: Address,
        engine: Address,
        asset: Address,
        grant: Grant,
    ) -> Address {
        env.deployer()
            .with_current_contract(BytesN::from_array(&env, &[0; 32]))
            .deploy_contract(
                soroban_sdk::ContractExecutable::Wasm(wasm),
                (
                    owner,
                    agent,
                    engine,
                    asset,
                    grant,
                    BytesN::from_array(&env, &[3; 32]),
                ),
            )
    }
}

#[test]
fn compiled_odc_constructor_rejects_deployment_without_owner_authorization() {
    let f = Fixture::new(true);
    let hash = f.env.deployer().upload_contract_wasm(ODC_WASM);
    let deployer = f.env.register(OdcConstructorDeployer, ());
    let grant = f.client().state().grant;
    f.env.mock_auths(&[]);
    // Unlike Env.register's recording bootstrap, this ordinary contract call
    // enforces authorization during the nested compiled constructor invocation.
    assert!(
        OdcConstructorDeployerClient::new(&f.env, &deployer)
            .try_deploy_odc(&hash, &f.owner, &f.agent, &f.engine, &f.asset, &grant)
            .is_err()
    );
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.balance(&f.odc), 1_000);
}

#[test]
fn selected_mixed_checks_and_custom_state_commit_only_the_final_map() {
    let f = Fixture::policy(STATE_POLICY_WASM);
    let c = f.client();
    c.transfer(&f.request(100));
    assert_eq!(f.used("daily"), 100);
    assert_eq!(f.used("total"), 100);
    assert_eq!(f.used("calls"), 1);
    assert_eq!(f.used("custom_count"), 1);
    let before = f.spent();
    let core = c.state();
    assert_eq!(c.try_transfer(&f.request(51)), Err(Ok(Error::PolicyDenied)));
    assert_eq!(f.spent(), before);
    assert_eq!(c.state(), core);
    c.transfer(&f.request(50));
    assert_eq!(f.used("daily"), 150);
    assert_eq!(f.used("total"), 150);
    assert_eq!(f.used("calls"), 2);
    f.env.ledger().with_mut(|l| l.timestamp = DAY * 2);
    c.transfer(&f.request(100));
    assert_eq!(f.used("daily"), 100);
    assert_eq!(f.used("total"), 250);
    assert_eq!(f.used("calls"), 3);
    let before = f.spent();
    f.env.ledger().with_mut(|l| l.timestamp = DAY * 3);
    assert_eq!(c.try_transfer(&f.request(1)), Err(Ok(Error::PolicyDenied)));
    assert_eq!(f.spent(), before);
    assert_eq!(f.balance(&f.recipient), 250);
    assert_eq!(c.state().nonce, 3);
}
#[test]
fn mixed_and_bundled_compiled_policy_have_identical_usage_maps() {
    let mixed = Fixture::policy(STATE_POLICY_WASM);
    let local = Fixture::policy(LOCAL_POLICY_WASM);
    for amount in [40, 30] {
        mixed.client().transfer(&mixed.request(amount));
        local.client().transfer(&local.request(amount));
        assert_eq!(
            mixed
                .spent()
                .to_xdr(&mixed.env)
                .iter()
                .collect::<std::vec::Vec<u8>>(),
            local
                .spent()
                .to_xdr(&local.env)
                .iter()
                .collect::<std::vec::Vec<u8>>()
        );
    }
    assert_eq!(
        mixed.balance(&mixed.recipient),
        local.balance(&local.recipient)
    );
    assert_eq!(mixed.client().state().nonce, local.client().state().nonce);
}
#[test]
fn bundled_rules_have_no_shared_fallback_and_shared_rules_fail_closed() {
    let local = Fixture::policy(LOCAL_POLICY_WASM);
    let mixed = Fixture::policy(STATE_POLICY_WASM);
    for f in [&local, &mixed] {
        f.client().set_engine(&Address::generate(&f.env), &0);
    }
    local.client().transfer(&local.request(10));
    assert_eq!(
        mixed.client().try_transfer(&mixed.request(10)),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(mixed.client().policy_spent(), None);
    assert_eq!(mixed.client().state().nonce, 0);
    assert_eq!(local.used("daily"), 10);
}
#[test]
fn failed_native_effect_or_custom_scalar_overflow_rolls_back_the_returned_map() {
    let f = Fixture::policy(STATE_POLICY_WASM);
    let c = f.client();
    StellarAssetClient::new(&f.env, &f.asset).set_authorized(&f.recipient, &false);
    assert!(c.try_transfer(&f.request(10)).is_err());
    assert_eq!(c.policy_spent(), None);
    assert_eq!(c.state().nonce, 0);
    StellarAssetClient::new(&f.env, &f.asset).set_authorized(&f.recipient, &true);
    let mut state = Grant::new(&f.env);
    state.set(
        String::from_str(&f.env, "custom_count"),
        u64::MAX.into_val(&f.env),
    );
    f.seed_spent(&state);
    assert_eq!(c.try_transfer(&f.request(10)), Err(Ok(Error::PolicyDenied)));
    assert_eq!(f.spent(), state);
    assert_eq!(c.state().nonce, 0);
    assert_eq!(f.balance(&f.recipient), 0);
}
#[test]
fn funding_pause_config_and_kernel_redeployment_preserve_arbitrary_spent() {
    let f = Fixture::policy(STATE_POLICY_WASM);
    let c = f.client();
    c.transfer(&f.request(10));
    let before = f.spent();
    StellarAssetClient::new(&f.env, &f.asset).mint(&f.odc, &100);
    c.set_pause(&true, &1);
    let mut deployment = c.deployment(1);
    deployment.grant.set(
        String::from_str(&f.env, "arbitrary"),
        Bytes::from_slice(&f.env, &[9, 8]).into_val(&f.env),
    );
    c.deploy_policy(&deployment);
    assert!(c.state().paused);
    assert_eq!(f.spent(), before);
    let mut wasm = Bytes::from_slice(&f.env, STATE_POLICY_WASM);
    wasm.extend_from_array(&[0, 5, 4, b's', b't', b'a', b't']);
    let hash = f.env.deployer().upload_contract_wasm(wasm);
    c.upgrade(&hash, &2);
    assert_eq!(f.spent(), before);
    assert_eq!(c.state().deployment_version, 3);
    assert!(c.state().paused);
    c.recover(&f.owner, &1, &0);
    assert_eq!(f.spent(), before);
    c.set_pause(&false, &4);
    c.transfer(&f.request(10));
    assert_eq!(f.used("custom_count"), 2);
    assert_eq!(f.used("total"), 20);
}
#[test]
fn owner_paths_ignore_malformed_spent_and_engine_availability() {
    let f = Fixture::policy(STATE_POLICY_WASM);
    let c = f.client();
    f.env.as_contract(&f.odc, || {
        let instance: BytesN<32> = f
            .env
            .storage()
            .instance()
            .get(&Key::PolicyInstance)
            .unwrap();
        let key: Vec<soroban_sdk::Val> = vec![
            &f.env,
            Symbol::new(&f.env, "Spent").into_val(&f.env),
            instance.into_val(&f.env),
        ];
        f.env.storage().persistent().set(&key, &true);
    });
    assert!(c.try_policy_spent().is_err());
    c.set_pause(&true, &1);
    c.set_engine(&Address::generate(&f.env), &1);
    c.recover(&f.owner, &10, &0);
    assert_eq!(f.balance(&f.owner), 10);
    assert!(c.state().paused);
    assert_eq!(c.state().nonce, 0);
}
#[test]
fn deployment_preserves_pause_and_only_pause_uses_its_explicit_next_version() {
    let f = Fixture::new(false);
    let c = f.client();
    c.set_pause(&true, &1);
    let mut deployment = c.deployment(1);
    deployment
        .grant
        .set(String::from_str(&f.env, "paused"), false.into_val(&f.env));
    c.deploy_policy(&deployment);
    assert!(c.state().paused);
    assert_eq!(c.state().deployment_version, 2);
    assert_eq!(c.try_set_pause(&false, &2), Err(Ok(Error::StaleRequest)));
    assert_eq!(c.try_set_pause(&false, &4), Err(Ok(Error::StaleRequest)));
    c.set_pause(&false, &3);
    assert!(!c.state().paused);
    let mut skipped = c.deployment(3);
    skipped.deployment_version = 5;
    assert_eq!(c.try_deploy_policy(&skipped), Err(Ok(Error::StaleRequest)));
}
#[test]
fn policy_without_checks_has_no_implicit_engine_veto_or_usage_write() {
    let f = Fixture::new(false);
    let c = f.client();
    c.set_engine(&Address::generate(&f.env), &0);
    let mut grant = Grant::new(&f.env);
    grant.set(
        String::from_str(&f.env, "daily_limit"),
        false.into_val(&f.env),
    );
    grant.set(String::from_str(&f.env, "max_calls"), 0u64.into_val(&f.env));
    c.set_grant(&grant, &1);
    c.transfer(&f.request(100));
    c.transfer(&f.request(100));
    assert_eq!(c.state().nonce, 2);
    assert_eq!(c.policy_spent(), None);
    assert_eq!(f.balance(&f.recipient), 200);
}
#[test]
fn nonce_overflow_and_insufficient_funds_preserve_operational_state() {
    let f = Fixture::new(false);
    let c = f.client();
    let before = c.state();
    assert_eq!(
        c.try_transfer(&f.request(2000)),
        Err(Ok(Error::InsufficientFunds))
    );
    assert_eq!(c.state(), before);
    let mut execution = c.envelope(&f.request(1));
    let mut state = before;
    state.nonce = u64::MAX;
    execution.nonce = u64::MAX;
    f.env
        .as_contract(&f.odc, || f.env.storage().instance().set(&0u32, &state));
    assert_eq!(c.try_execute(&execution), Err(Ok(Error::Overflow)));
    assert_eq!(c.state(), state);
    assert_eq!(c.policy_spent(), None);
}
#[test]
fn actual_signed_x402_effect_and_failure_share_functional_spent() {
    for wasm in [STATE_POLICY_WASM, LOCAL_POLICY_WASM] {
        let (f, key) = x402_configure(Fixture::policy(wasm));
        let auth = x402_host_entry(&f, &key, 50, 7);
        f.env.set_auths(&[auth]);
        token::Client::new(&f.env, &f.asset).transfer(&f.odc, &f.recipient, &50);
        assert_eq!(f.balance(&f.recipient), 50);
        assert_eq!(f.used("daily"), 50);
        assert_eq!(f.used("custom_count"), 1);
        let before = f.spent();
        let core = f.client().state();
        f.env.mock_all_auths();
        StellarAssetClient::new(&f.env, &f.asset).set_authorized(&f.recipient, &false);
        let auth = x402_host_entry(&f, &key, 50, 8);
        f.env.set_auths(&[auth]);
        assert!(
            token::Client::new(&f.env, &f.asset)
                .try_transfer(&f.odc, &f.recipient, &50)
                .is_err()
        );
        assert_eq!(f.spent(), before);
        assert_eq!(f.client().state(), core);
        assert_eq!(f.balance(&f.recipient), 50);
    }
}
#[test]
fn execute_and_x402_share_usage_limits_nonce_and_replay() {
    let (f, key) = x402_configure(Fixture::policy(STATE_POLICY_WASM));
    let c = f.client();
    let first = c.envelope(&f.request(100));
    c.execute(&first);
    assert_eq!(f.used("daily"), 100);
    let auth = x402_host_entry(&f, &key, 50, 9);
    f.env.set_auths(&[auth]);
    token::Client::new(&f.env, &f.asset).transfer(&f.odc, &f.recipient, &50);
    assert_eq!(f.used("daily"), 150);
    assert_eq!(f.used("total"), 150);
    assert_eq!(f.used("calls"), 2);
    assert_eq!(f.balance(&f.recipient), 150);
    f.env.mock_all_auths();
    let before = f.spent();
    assert_eq!(c.try_execute(&first), Err(Ok(Error::Replay)));
    assert_eq!(c.try_transfer(&f.request(1)), Err(Ok(Error::PolicyDenied)));
    assert_eq!(f.spent(), before);
}

#[test]
fn owner_atomic_x402_updates_bind_new_version_and_derived_agent_key() {
    let (f, old_key) = x402_setup_compiled(false);
    let c = f.client();
    let payload = BytesN::from_array(&f.env, &[42; 32]);
    let old_execution = c.envelope(&f.request(50));
    let old_signature = x402_signed(&f, &old_key, old_execution, &payload);
    let mut policy = c.deployment(c.state().deployment_version);
    policy
        .grant
        .set(String::from_str(&f.env, "unrelated"), true.into_val(&f.env));
    policy.x402_enabled = true;
    c.deploy_policy(&policy);
    assert!(
        f.env
            .as_contract(&f.odc, || f.env.storage().instance().has(&Key::X402Config))
    );
    assert_eq!(
        f.env.try_invoke_contract_check_auth::<Error>(
            &f.odc,
            &payload,
            old_signature.into_val(&f.env),
            &x402_context(&f, 50)
        ),
        Err(Ok(Error::StaleRequest))
    );
    let new_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let mut encoded = Bytes::from_slice(&f.env, &[0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0]);
    encoded.extend_from_array(&new_key.verifying_key().to_bytes());
    let new_agent = Address::from_xdr(&f.env, &encoded).unwrap();
    let mut policy = c.deployment(c.state().deployment_version);
    policy.agent = new_agent.clone();
    policy.x402_enabled = true;
    c.deploy_policy(&policy);
    let wrong_key = x402_signed(&f, &old_key, c.envelope(&f.request(50)), &payload);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                wrong_key.into_val(&f.env),
                &x402_context(&f, 50)
            )
            .is_err()
    );
    assert_eq!(c.state().nonce, 0);
    let auth = x402_host_entry(&f, &new_key, 50, 9);
    f.env.set_auths(&[auth]);
    token::Client::new(&f.env, &f.asset).transfer(&f.odc, &f.recipient, &50);
    assert_eq!(f.balance(&f.recipient), 50);
    f.env.mock_all_auths();
    let mut policy = c.deployment(c.state().deployment_version);
    policy.x402_enabled = false;
    c.deploy_policy(&policy);
    let auth = x402_host_entry(&f, &new_key, 1, 10);
    f.env.set_auths(&[auth]);
    assert!(
        token::Client::new(&f.env, &f.asset)
            .try_transfer(&f.odc, &f.recipient, &1)
            .is_err()
    );
    assert_eq!(f.balance(&f.recipient), 50);
    f.env.mock_all_auths();
    let before = c.state();
    let mut policy = c.deployment(before.deployment_version);
    policy.agent = Address::generate(&f.env);
    policy.x402_enabled = true;
    assert_eq!(c.try_deploy_policy(&policy), Err(Ok(Error::InvalidActor)));
    assert_eq!(c.state(), before);
}

#[test]
fn a_selected_engine_receives_no_wallet_token_authorization() {
    let f = Fixture::policy(STATE_POLICY_WASM);
    let c = f.client();
    let engine = f.env.register(Steal, ());
    c.set_engine(&engine, &0);
    let request = f.request(10);
    f.env.mock_auths(&[MockAuth {
        address: &f.agent,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "execute",
            args: (c.envelope(&request),).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    let before = c.state();
    assert_eq!(c.try_transfer(&request), Err(Ok(Error::PolicyDenied)));
    assert_eq!(c.state(), before);
    assert_eq!(c.policy_spent(), None);
    assert_eq!(f.balance(&engine), 0);
    assert_eq!(f.balance(&f.odc), 1000);
}

#[contract]
struct DataOnlyEngine;
#[contractimpl]
impl DataOnlyEngine {
    pub fn total_cap(
        env: Env,
        request: EngineRequest,
        state: EngineState,
    ) -> Result<EngineResult, EngineError> {
        let mut result = allowit_policy_rules::total_cap(env.clone(), request, state)?;
        result.spent.set(
            String::from_str(&env, "owner"),
            env.current_contract_address().into_val(&env),
        );
        result
            .spent
            .set(String::from_str(&env, "nonce"), 0u64.into_val(&env));
        result.spent.set(
            String::from_str(&env, "deployment_version"),
            0u64.into_val(&env),
        );
        result.spent.set(
            String::from_str(&env, "code"),
            String::from_str(&env, "data-only").into_val(&env),
        );
        Ok(result)
    }
}
#[test]
fn engine_returned_business_data_cannot_replace_owner_code_asset_or_ordering() {
    let f = Fixture::policy(STATE_POLICY_WASM);
    let c = f.client();
    let engine = f.env.register(DataOnlyEngine, ());
    c.set_engine(&engine, &0);
    let before = c.state();
    let binding = c.policy_binding();
    c.transfer(&f.request(10));
    let after = c.state();
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.agent, before.agent);
    assert_eq!(after.asset, before.asset);
    assert_eq!(after.grant, before.grant);
    assert_eq!(after.deployment_version, before.deployment_version);
    assert_eq!(after.nonce, 1);
    assert_eq!(c.policy_binding().module_digest, binding.module_digest);
    assert_eq!(
        Address::try_from_val(
            &f.env,
            &f.spent().get(String::from_str(&f.env, "owner")).unwrap()
        )
        .unwrap(),
        engine
    );
    assert_eq!(f.balance(&f.recipient), 10);
}
#[test]
fn engine_proposals_do_not_write_and_only_the_selected_final_map_commits() {
    let f = Fixture::new(true);
    let c = f.client();
    let mut grant = c.state().grant;
    grant.set(
        String::from_str(&f.env, "daily_limit"),
        100u64.into_val(&f.env),
    );
    c.set_grant(&grant, &0);
    let execution = c.envelope(&f.request(10));
    f.env.as_contract(&f.odc, || {
        let host = NativePolicyHost {
            env: &f.env,
            engine: f.engine.clone(),
            grant: grant.clone(),
            request: EngineRequest {
                wallet: f.odc.clone(),
                agent: f.agent.clone(),
                asset: f.asset.clone(),
                token: String::from_str(&f.env, "USDC"),
                decimals: 7,
                recipient: f.recipient.clone(),
                amount: 10,
                operation_id: execution.operation_id,
                nonce: 0,
                deployment_version: 1,
                expires_at: DAY + 100,
                now: DAY + 10,
            },
        };
        let initial = Grant::new(&f.env);
        let proposal = host
            .engine_check("daily_cap", &initial, Vec::new(&f.env))
            .unwrap();
        assert!(proposal.approval);
        assert!(!proposal.spent.is_empty());
        let instance = f
            .env
            .storage()
            .instance()
            .get(&Key::PolicyInstance)
            .unwrap();
        let storage = NativePolicyStorage {
            env: &f.env,
            policy_instance: instance,
        };
        assert_eq!(storage.load(), Ok(None));
        // Returning the earlier map deliberately discards an unused proposal; there is no hidden merge.
        assert!(!storage.commit(&None, &initial));
        assert_eq!(storage.load(), Ok(None));
    });
    assert_eq!(c.policy_spent(), None);
    assert_eq!(c.state().nonce, 0);
}

#[contract]
struct InvalidKeysEngine;
#[contractimpl]
impl InvalidKeysEngine {
    pub fn total_cap(env: Env, _request: EngineRequest, mut state: EngineState) -> EngineResult {
        let invalid_utf8 = state
            .grant
            .get(String::from_str(&env, "invalid_utf8"))
            .and_then(|v| bool::try_from_val(&env, &v).ok())
            .unwrap_or(false);
        let mut raw = soroban_sdk::Map::<soroban_sdk::Val, soroban_sdk::Val>::try_from_val(
            &env,
            &state.spent.to_val(),
        )
        .unwrap();
        let name = if invalid_utf8 {
            String::from_bytes(&env, &[0xc3, 0x28]).into_val(&env)
        } else {
            Symbol::new(&env, "not_a_string").into_val(&env)
        };
        raw.set(name, true.into_val(&env));
        state.spent = Grant::try_from_val(&env, &raw.to_val()).unwrap();
        EngineResult {
            approval: true,
            spent: state.spent,
        }
    }
}
#[test]
fn malformed_engine_names_cannot_poison_persistent_usage_or_sdk_views() {
    for invalid_utf8 in [false, true] {
        let f = Fixture::policy(STATE_POLICY_WASM);
        let c = f.client();
        let engine = f.env.register(InvalidKeysEngine, ());
        let mut policy = c.deployment(0);
        policy.engine = engine;
        policy.grant.set(
            String::from_str(&f.env, "invalid_utf8"),
            invalid_utf8.into_val(&f.env),
        );
        c.deploy_policy(&policy);
        let before = c.state();
        assert_eq!(c.try_transfer(&f.request(10)), Err(Ok(Error::InvalidState)));
        assert_eq!(c.state(), before);
        assert_eq!(c.policy_spent(), None);
        assert_eq!(f.balance(&f.recipient), 0);
        c.set_pause(&true, &2);
        c.recover(&f.owner, &1, &0);
    }
}
#[test]
fn grant_named_keys_are_string_utf8_and_unrelated_raw_values_are_preserved() {
    let f = Fixture::new(false);
    let c = f.client();
    let before = c.state();
    for key in [
        Symbol::new(&f.env, "symbol").into_val(&f.env),
        String::from_bytes(&f.env, &[0xff]).into_val(&f.env),
    ] {
        let mut raw = soroban_sdk::Map::<soroban_sdk::Val, soroban_sdk::Val>::new(&f.env);
        raw.set(key, true.into_val(&f.env));
        let mut policy = c.deployment(0);
        policy.grant = Grant::try_from_val(&f.env, &raw.to_val()).unwrap();
        assert_eq!(c.try_deploy_policy(&policy), Err(Ok(Error::InvalidGrant)));
        assert_eq!(c.state(), before);
    }
    let mut data = Grant::new(&f.env);
    let opaque = String::from_bytes(&f.env, &[0xff]);
    data.set(
        String::from_str(&f.env, "opaque_value"),
        opaque.clone().into_val(&f.env),
    );
    c.set_grant(&data, &0);
    assert_eq!(
        String::try_from_val(
            &f.env,
            &c.state()
                .grant
                .get(String::from_str(&f.env, "opaque_value"))
                .unwrap()
        )
        .unwrap(),
        opaque
    );
    assert!(
        allowit_wallet_protocol::PolicyValue::from_raw(&f.env, &opaque.into_val(&f.env)).is_err()
    );
}

#[test]
fn state_load_renews_constructor_lifetime_and_receipts_keep_persistent_lifetime() {
    use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};
    for compiled in [false, true] {
        let f = Fixture::new(compiled);
        assert_eq!(
            f.env
                .as_contract(&f.odc, || f.env.storage().instance().get_ttl()),
            TTL_EXTEND
        );
        f.env
            .ledger()
            .with_mut(|ledger| ledger.sequence_number += TTL_THRESHOLD + 1);
        f.client().state();
        assert_eq!(
            f.env
                .as_contract(&f.odc, || f.env.storage().instance().get_ttl()),
            TTL_EXTEND
        );
        let request = f.request(1);
        let execution = f.client().envelope(&request);
        let key = Key::Operation(execution.operation_id.clone());
        f.client().execute(&execution);
        assert_eq!(
            f.env
                .as_contract(&f.odc, || f.env.storage().persistent().get_ttl(&key)),
            f.env.storage().max_ttl()
        );
        assert_eq!(f.client().try_execute(&execution), Err(Ok(Error::Replay)));
    }
}
