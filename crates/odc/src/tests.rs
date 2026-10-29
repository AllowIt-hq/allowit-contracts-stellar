extern crate std;

use super::*;
use core::ops::Deref;

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
    pub fn evaluate(env: Env, context: EngineContext) -> bool {
        env.storage().instance().set(&0u32, &context);
        true
    }
}
#[contract]
struct Deny;
#[contractimpl]
impl Deny {
    pub fn evaluate(_env: Env, _context: EngineContext) -> bool {
        false
    }
}
#[contract]
struct Trap;
#[contractimpl]
impl Trap {
    pub fn evaluate(_env: Env, _context: EngineContext) -> bool {
        panic!("malicious engine")
    }
}
#[contract]
struct Steal;
#[contractimpl]
impl Steal {
    pub fn evaluate(env: Env, context: EngineContext) -> bool {
        token::Client::new(&env, &context.asset).transfer(
            &context.wallet,
            env.current_contract_address(),
            &1,
        );
        true
    }
}

struct TestClient<'a> {
    client: OdcClient<'a>,
    env: &'a Env,
    wallet: &'a Address,
}
impl<'a> TestClient<'a> {
    fn new(env: &'a Env, address: &'a Address) -> Self {
        Self {
            client: OdcClient::new(env, address),
            env,
            wallet: address,
        }
    }
    fn envelope(&self, request: &TransferRequest) -> ExecutionRequest {
        let installed = self.client.policy_binding();
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&request.nonce.checked_add(1).unwrap().to_be_bytes());
        ExecutionRequest {
            policy_instance: installed.policy_instance,
            operation_id: BytesN::from_array(self.env, &id),
            nonce: request.nonce,
            revision: request.revision,
            expires_at: request.expires_at,
            invocation: allowit_wallet_protocol::PolicyInvocation {
                module_digest: installed.module_digest,
                entrypoint: installed.entrypoint,
                argument_schema_digest: installed.argument_schema_digest,
                arguments: Sep41TransferArgs {
                    token: self.client.state().grant.asset,
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
    type Target = OdcClient<'a>;
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
        let grant = Grant {
            asset: asset.clone(),
            recipients: vec![&env, recipient.clone()],
            per_transfer: 100,
            daily_limit: 150,
            total_limit: 250,
            max_calls: 3,
            expires_at: DAY * 10,
        };
        let args = (
            owner.clone(),
            agent.clone(),
            engine.clone(),
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
            revision: state.revision,
            expires_at: self.env.ledger().timestamp() + 100,
        }
    }
    fn balance(&self, address: &Address) -> i128 {
        token::Client::new(&self.env, &self.asset).balance(address)
    }
}

#[test]
fn malicious_allow_cannot_expand_local_grant_or_replay() {
    let f = Fixture::new(false);
    let c = f.client();
    assert_eq!(
        c.try_transfer(&f.request(101)),
        Err(Ok(Error::BudgetExceeded))
    );
    let first = f.request(100);
    c.transfer(&first);
    assert_eq!(c.state().spent_total, 100);
    assert_eq!(f.balance(&f.recipient), 100);
    assert_eq!(c.try_transfer(&first), Err(Ok(Error::Replay)));
    let before = c.state();
    assert_eq!(
        c.try_transfer(&f.request(51)),
        Err(Ok(Error::BudgetExceeded))
    );
    let mut wrong = f.request(1);
    wrong.recipient = Address::generate(&f.env);
    assert_eq!(c.try_transfer(&wrong), Err(Ok(Error::InvalidRecipient)));
    let mut expired = f.request(1);
    expired.expires_at = f.env.ledger().timestamp();
    assert_eq!(c.try_transfer(&expired), Err(Ok(Error::Expired)));
    assert_eq!(c.try_transfer(&f.request(0)), Err(Ok(Error::InvalidAmount)));
    assert_eq!(
        c.try_transfer(&f.request(-1)),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(c.state(), before);
    c.transfer(&f.request(50));
    f.env.ledger().with_mut(|l| l.timestamp = DAY * 2);
    c.transfer(&f.request(100));
    assert_eq!(c.state().spent_total, 250);
    assert_eq!(c.state().calls, 3);
    f.env.ledger().with_mut(|l| l.timestamp = DAY * 3);
    assert_eq!(
        c.try_transfer(&f.request(1)),
        Err(Ok(Error::BudgetExceeded))
    );
    assert_eq!(f.balance(&f.recipient), 250);
}

#[test]
fn canonical_context_and_calendar_rollover_are_local() {
    let f = Fixture::new(false);
    f.client().transfer(&f.request(100));
    f.env.ledger().with_mut(|l| l.timestamp = DAY * 2);
    let req = f.request(1);
    f.client().transfer(&req);
    let context: EngineContext = f
        .env
        .as_contract(&f.engine, || f.env.storage().instance().get(&0u32).unwrap());
    assert_eq!(context.wallet, f.odc);
    assert_eq!(context.agent, f.agent);
    assert_eq!(context.asset, f.asset);
    assert_eq!(context.request, req);
    assert_eq!(context.spent_daily, 0);
    assert_eq!(context.spent_total, 100);
    assert_eq!(context.calls, 1);
    assert_eq!(context.now, DAY * 2);
    assert_eq!(f.client().state().spent_daily, 1);
    f.env.ledger().with_mut(|l| l.timestamp = DAY);
    assert_eq!(
        f.client().try_transfer(&f.request(1)),
        Err(Ok(Error::ClockRegression))
    );
}

#[test]
fn failed_engines_cannot_block_owner_pause_recovery_or_reconfiguration() {
    let f = Fixture::new(false);
    let c = f.client();
    let deny = f.env.register(Deny, ());
    let trap = f.env.register(Trap, ());
    let missing = Address::generate(&f.env);
    for engine in [deny, trap, missing] {
        c.set_engine(&engine, &c.state().revision);
        let before = c.state();
        assert_eq!(c.try_transfer(&f.request(1)), Err(Ok(Error::EngineDenied)));
        assert_eq!(c.state(), before);
        c.set_paused(&true, &c.state().revision);
        assert_eq!(c.try_transfer(&f.request(1)), Err(Ok(Error::Paused)));
        c.recover(&f.owner, &1, &c.state().revision);
        c.set_paused(&false, &c.state().revision);
        assert_eq!(c.state().spent_total, 0);
        assert_eq!(c.state().nonce, 0);
    }
    assert_eq!(f.balance(&f.owner), 3);
    c.set_engine(&f.engine, &c.state().revision);
    c.transfer(&f.request(1));
}

#[test]
fn engine_receives_no_wallet_spending_authority() {
    let f = Fixture::new(false);
    let engine = f.env.register(Steal, ());
    f.client().set_engine(&engine, &0);
    // Mock only agent auth for the exact gateway call. No blanket wallet auth.
    let req = f.request(10);
    f.env.mock_auths(&[MockAuth {
        address: &f.agent,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "execute",
            args: (f.client().envelope(&req),).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    let before = f.client().state();
    assert_eq!(f.client().try_transfer(&req), Err(Ok(Error::EngineDenied)));
    assert_eq!(f.client().state(), before);
    assert_eq!(f.balance(&engine), 0);
    assert_eq!(f.balance(&f.odc), 1_000);
}

#[test]
fn owner_controls_require_owner_not_agent_and_revision_is_exact() {
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
            fn_name: "set_paused",
            args: (true, 0u64).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    assert!(c.try_set_paused(&true, &0).is_err());
    f.env.mock_auths(&[MockAuth {
        address: &f.owner,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "set_paused",
            args: (true, 0u64).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);
    c.set_paused(&true, &0);
    f.env.mock_all_auths();
    assert_eq!(c.try_set_paused(&false, &0), Err(Ok(Error::StaleRequest)));
    assert_eq!(c.state().revision, 1);
    assert_eq!(c.try_unsupported(), Err(Ok(Error::UnsupportedOperation)));
}

#[test]
fn funding_and_all_admin_mutations_preserve_consumption() {
    let f = Fixture::new(false);
    let c = f.client();
    c.transfer(&f.request(20));
    let before = c.state();
    StellarAssetClient::new(&f.env, &f.asset).mint(&f.odc, &100);
    let mut grant = before.grant.clone();
    grant.daily_limit = 10;
    c.set_grant(&grant, &0);
    let agent = Address::generate(&f.env);
    c.set_agent(&agent, &1);
    c.set_engine(&Address::generate(&f.env), &2);
    c.recover(&f.owner, &50, &3);
    let next_owner = Address::generate(&f.env);
    c.transfer_owner(&next_owner, &4);
    let after = c.state();
    assert_eq!(after.revision, 5);
    assert_eq!(after.spent_daily, before.spent_daily);
    assert_eq!(after.spent_day, before.spent_day);
    assert_eq!(after.spent_total, before.spent_total);
    assert_eq!(after.calls, before.calls);
    assert_eq!(after.nonce, before.nonce);
    assert_eq!(after.owner, next_owner);
    assert_eq!(f.balance(&f.owner), 50);
}

#[test]
fn arithmetic_overflow_expiry_and_sac_failure_leave_state_unchanged() {
    let f = Fixture::new(false);
    let c = f.client();
    let mut grant = c.state().grant;
    grant.per_transfer = i128::MAX;
    grant.daily_limit = i128::MAX;
    grant.total_limit = i128::MAX;
    c.set_grant(&grant, &0);
    c.transfer(&f.request(1));
    let before = c.state();
    assert_eq!(
        c.try_transfer(&f.request(i128::MAX)),
        Err(Ok(Error::Overflow))
    );
    assert_eq!(
        c.try_transfer(&f.request(2_000)),
        Err(Ok(Error::InsufficientFunds))
    );
    assert_eq!(c.state(), before);
    f.env.ledger().with_mut(|l| l.timestamp = grant.expires_at);
    assert_eq!(c.try_transfer(&f.request(1)), Err(Ok(Error::Expired)));
    assert_eq!(c.state(), before);
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
fn compiled_odc_upgrade_keeps_address_state_and_rejects_old_requests() {
    let f = Fixture::new(true);
    let c = f.client();
    c.transfer(&f.request(10));
    c.set_engine(&Address::generate(&f.env), &0);
    let old_request = f.request(1);
    let before = c.state();
    let mut replacement = soroban_sdk::Bytes::from_slice(&f.env, ODC_WASM);
    // A valid custom section gives the compatible compiled code a new hash.
    replacement.extend_from_array(&[0, 5, 4, b'o', b'd', b'c', b'2']);
    let hash = f.env.deployer().upload_contract_wasm(replacement);
    c.upgrade(&hash, &before.revision);
    let after = c.state();
    let mut expected = before;
    expected.revision += 1;
    assert_eq!(after, expected);
    assert_eq!(c.address, f.odc);
    assert_eq!(f.odc.executable(), Some(Executable::Wasm(hash)));
    assert_eq!(c.try_transfer(&old_request), Err(Ok(Error::StaleRequest)));
    c.set_paused(&true, &c.state().revision);
    c.recover(&f.owner, &1, &c.state().revision);
    c.set_engine(&f.engine, &c.state().revision);
    c.set_paused(&false, &c.state().revision);
    c.transfer(&f.request(1));
    assert_eq!(c.state().spent_total, 11);
}

#[test]
fn call_count_is_independent_of_available_money_and_caps() {
    let f = Fixture::new(false);
    let c = f.client();
    let mut grant = c.state().grant;
    grant.max_calls = 1;
    c.set_grant(&grant, &0);
    c.transfer(&f.request(1));
    assert_eq!(
        c.try_transfer(&f.request(1)),
        Err(Ok(Error::BudgetExceeded))
    );
    assert_eq!(c.state().spent_total, 1);
}

#[test]
fn owner_handoff_requires_candidate_acceptance_and_invalidates_old_requests() {
    let f = Fixture::new(false);
    let c = f.client();
    let candidate = Address::generate(&f.env);
    let args: soroban_sdk::Vec<soroban_sdk::Val> = (candidate.clone(), 0u64).into_val(&f.env);
    f.env.mock_auths(&[MockAuth {
        address: &f.owner,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "transfer_owner",
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
                fn_name: "transfer_owner",
                args: args.clone(),
                sub_invokes: &[],
            },
        },
        MockAuth {
            address: &candidate,
            invoke: &MockAuthInvoke {
                contract: &f.odc,
                fn_name: "transfer_owner",
                args,
                sub_invokes: &[],
            },
        },
    ]);
    c.transfer_owner(&candidate, &0);
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
    // The compiled ODC exports no __check_auth. An agent credential is not
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
fn invalid_asset_change_and_failed_upgrade_preserve_state() {
    let f = Fixture::new(false);
    let c = f.client();
    let before = c.state();
    let mut grant = before.grant.clone();
    grant.asset = Address::generate(&f.env);
    assert_eq!(
        c.try_set_grant(&grant, &0),
        Err(Ok(Error::UnsupportedAsset))
    );
    assert!(
        c.try_upgrade(&BytesN::from_array(&f.env, &[0; 32]), &0)
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
    for owner in [&f.owner, &f.agent, &f.engine, &f.odc] {
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

#[expect(
    dead_code,
    reason = "This trait generates a client for compiled parent Wasm, not a local implementation."
)]
#[soroban_sdk::contractclient(name = "IntegratedParentClient")]
pub trait IntegratedParentInterface {
    fn engine(env: Env) -> Address;
    fn upgrade_engine(env: Env, new_hash: BytesN<32>, expected_revision: u64);
}

#[test]
fn compiled_parent_engine_upgrade_vetoes_two_odcs_without_custody_authority() {
    const PARENT_WASM: &[u8] =
        include_bytes!("../../../target/wasm32v1-none/release/allowit_engine_parent.wasm");
    const DENY_WASM: &[u8] = include_bytes!("../../../target/test-fixtures/engine_deny.wasm");
    let f = Fixture::new(true);
    let env = &f.env;
    let admin = Address::generate(env);
    let engine_hash = env.deployer().upload_contract_wasm(ENGINE_WASM);
    let deny_hash = env.deployer().upload_contract_wasm(DENY_WASM);
    env.mock_all_auths_allowing_non_root_auth();
    let parent = env.register(PARENT_WASM, (admin.clone(), engine_hash.clone()));
    let parent_client = IntegratedParentClient::new(env, &parent);
    let shared_engine = parent_client.engine();
    f.client().set_engine(&shared_engine, &0);
    let owner_two = Address::generate(env);
    let agent_two = Address::generate(env);
    let grant = f.client().state().grant;
    let odc_two = env.register(
        ODC_WASM,
        (
            owner_two.clone(),
            agent_two,
            shared_engine.clone(),
            grant,
            BytesN::from_array(env, &[2; 32]),
        ),
    );
    env.mock_all_auths();
    StellarAssetClient::new(env, &f.asset).mint(&odc_two, &1_000);
    let second = TestClient::new(env, &odc_two);
    f.client().transfer(&f.request(10));
    let second_request = |amount| {
        let state = second.state();
        TransferRequest {
            recipient: f.recipient.clone(),
            amount,
            nonce: state.nonce,
            revision: state.revision,
            expires_at: env.ledger().timestamp() + 100,
        }
    };
    second.transfer(&second_request(10));
    let before_one = f.client().state();
    let before_two = second.state();
    let token_before = f.balance(&f.recipient);
    // Exact mock authorization validates the parent/admin binding. This is not
    // a claim that a native 2-of-3 cryptographic quorum was exercised.
    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &parent,
            fn_name: "upgrade_engine",
            args: (deny_hash.clone(), 0u64).into_val(env),
            sub_invokes: &[],
        },
    }]);
    parent_client.upgrade_engine(&deny_hash, &0);
    assert_eq!(parent_client.engine(), shared_engine);
    assert_eq!(
        shared_engine.executable(),
        Some(Executable::Wasm(deny_hash))
    );
    env.mock_all_auths();
    assert_eq!(
        f.client().try_transfer(&f.request(1)),
        Err(Ok(Error::EngineDenied))
    );
    assert_eq!(
        second.try_transfer(&second_request(1)),
        Err(Ok(Error::EngineDenied))
    );
    assert_eq!(f.client().state(), before_one);
    assert_eq!(second.state(), before_two);
    assert_eq!(f.balance(&f.recipient), token_before);
    assert_eq!(f.client().address, f.odc);
    assert_eq!(second.address, odc_two);
    // Neither owner's emergency control depends on the now-denying engine.
    f.client().set_paused(&true, &before_one.revision);
    f.client()
        .recover(&f.owner, &1, &f.client().state().revision);
    second.set_paused(&true, &before_two.revision);
    second.recover(&owner_two, &1, &second.state().revision);
    for (state, before) in [
        (f.client().state(), before_one),
        (second.state(), before_two),
    ] {
        assert_eq!(state.grant, before.grant);
        assert_eq!(state.spent_daily, before.spent_daily);
        assert_eq!(state.spent_total, before.spent_total);
        assert_eq!(state.calls, before.calls);
        assert_eq!(state.nonce, before.nonce);
        assert_eq!(state.owner, before.owner);
    }
    env.mock_auths(&[MockAuth {
        address: &admin,
        invoke: &MockAuthInvoke {
            contract: &parent,
            fn_name: "upgrade_engine",
            args: (engine_hash.clone(), 1u64).into_val(env),
            sub_invokes: &[],
        },
    }]);
    parent_client.upgrade_engine(&engine_hash, &1);
    assert_eq!(parent_client.engine(), shared_engine);
    env.mock_all_auths();
    f.client().set_paused(&false, &f.client().state().revision);
    second.set_paused(&false, &second.state().revision);
    f.client().transfer(&f.request(1));
    second.transfer(&second_request(1));
    assert_eq!(f.client().state().spent_total, 11);
    assert_eq!(second.state().spent_total, 11);
    assert_eq!(
        f.client().try_transfer(&f.request(101)),
        Err(Ok(Error::BudgetExceeded))
    );
    assert_eq!(
        second.try_transfer(&second_request(101)),
        Err(Ok(Error::BudgetExceeded))
    );
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
            .try_deploy_odc(&hash, &f.owner, &f.agent, &f.engine, &grant)
            .is_err()
    );
    assert_eq!(f.client().state().nonce, 0);
    assert_eq!(f.balance(&f.odc), 1_000);
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
    assert_eq!(f.client().state().spent_total, 10);
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
    client.recover(&f.owner, &10, &before.revision);
    let after = client.state();
    assert_eq!(after.spent_total, before.spent_total);
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
fn local_expiry_cannot_exceed_the_owner_grant_even_when_engine_allows() {
    let f = Fixture::new(false);
    let mut request = f.request(1);
    request.expires_at = f.client().state().grant.expires_at + 1;
    assert_eq!(f.client().try_transfer(&request), Err(Ok(Error::Expired)));
    assert_eq!(f.client().state().nonce, 0);
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
    grant.recipients.push_back(allowed.clone());
    env.mock_all_auths_allowing_non_root_auth();
    let wallet = env.register(
        POLICY_WASM,
        (
            f.owner.clone(),
            f.agent.clone(),
            f.engine.clone(),
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
        revision: 0,
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
    assert_eq!(client.state().spent_total, 10);
    assert_eq!(client.state().nonce, 1);
}

#[path = "test_generated_financial_policy.rs"]
#[rustfmt::skip]
#[allow(unused_braces)]
mod financial_policy;

#[test]
fn compiled_financial_guards_use_exact_native_units_without_rounding() {
    let f = Fixture::new(false);
    assert_eq!(
        financial_policy::SOURCE_PROFILE,
        "allowit-stellar-transfer-v1"
    );
    assert_eq!(financial_policy::SOURCE_PROFILE_VERSION, 1);
    assert_eq!(
        financial_policy::ADMITTED_OPERATION,
        "stellar::sep41_transfer"
    );
    assert_eq!(
        BytesN::from_array(&f.env, &financial_policy::SOURCE_HASH),
        f.env
            .crypto()
            .sha256(&Bytes::from_slice(
                &f.env,
                include_bytes!("../policy/financial-policy.rs")
            ))
            .to_bytes()
    );
    assert_eq!(
        BytesN::from_array(&f.env, &financial_policy::ARGUMENT_SCHEMA_HASH),
        f.env
            .crypto()
            .sha256(&Bytes::from_slice(&f.env, ARGUMENT_SCHEMA_DESCRIPTOR))
            .to_bytes()
    );
    let mut context = PolicyContext {
        asset: f.asset,
        recipient: Address::from_str(
            &f.env,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        ),
        token: soroban_sdk::String::from_str(&f.env, "USDC"),
        decimals: 7,
        amount: 20_000_000,
        spent_daily: 30_000_000,
        spent_total: 30_000_000,
        calls: 0,
        now: DAY + 100,
        spent_day: 1,
    };
    assert!(financial_policy::execute(&context));
    context.amount += 1;
    assert!(!financial_policy::execute(&context));
    context.amount = 20_000_000;
    context.spent_daily += 1;
    context.spent_total += 1;
    assert!(!financial_policy::execute(&context));
    context.now = DAY * 2;
    assert!(financial_policy::execute(&context));
    context.spent_day = 3;
    assert!(!financial_policy::execute(&context));
    context.spent_day = 2;
    context.spent_daily = i128::MAX;
    context.spent_total = i128::MAX;
    assert!(!financial_policy::execute(&context));
    context.spent_daily = 0;
    context.spent_total = 0;
    context.decimals = 6;
    assert!(!financial_policy::execute(&context));
    context.decimals = 7;
    context.token = soroban_sdk::String::from_str(&f.env, "NOT_USDC");
    assert!(!financial_policy::execute(&context));
}

#[path = "test_generated_bool_policy.rs"]
#[rustfmt::skip]
#[allow(unused_braces)]
mod bool_policy;

#[test]
fn compiled_fallible_boolean_preserves_false_and_propagates_errors_before_or() {
    let f = Fixture::new(false);
    assert_eq!(bool_policy::SOURCE_PROFILE, "allowit-stellar-transfer-v1");
    assert_eq!(bool_policy::SOURCE_PROFILE_VERSION, 1);
    assert_eq!(bool_policy::ADMITTED_OPERATION, "stellar::sep41_transfer");
    assert_eq!(
        BytesN::from_array(&f.env, &bool_policy::SOURCE_HASH),
        f.env
            .crypto()
            .sha256(&Bytes::from_slice(
                &f.env,
                include_bytes!("../policy/bool-policy.rs")
            ))
            .to_bytes()
    );
    assert_eq!(
        BytesN::from_array(&f.env, &bool_policy::ARGUMENT_SCHEMA_HASH),
        f.env
            .crypto()
            .sha256(&Bytes::from_slice(&f.env, ARGUMENT_SCHEMA_DESCRIPTOR))
            .to_bytes()
    );
    let mut context = PolicyContext {
        asset: f.asset,
        recipient: f.recipient,
        token: soroban_sdk::String::from_str(&f.env, "USDC"),
        decimals: 7,
        amount: 20_000_001,
        spent_daily: 0,
        spent_total: 0,
        calls: 0,
        now: DAY,
        spent_day: 1,
    };
    // The authored boolean is false, which is a valid value rather than a rejected guard.
    assert!(bool_policy::execute(&context));
    context.amount = 1;
    assert!(bool_policy::execute(&context));
    // Wrong denomination is an error in amount_at_most. It must propagate
    // before the unused boolean binding or the later `|| true` can allow it.
    context.token = soroban_sdk::String::from_str(&f.env, "OTHER");
    assert!(!bool_policy::execute(&context));
    context.token = soroban_sdk::String::from_str(&f.env, "USDC");
    context.decimals = 6;
    assert!(!bool_policy::execute(&context));
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
    let grant = Grant {
        asset: native.clone(),
        recipients: vec![&env, recipient.clone()],
        per_transfer: 100,
        daily_limit: 150,
        total_limit: 250,
        max_calls: 3,
        expires_at: DAY * 10,
    };
    let wallet = env.register(
        XLM_POLICY_WASM,
        (
            owner.clone(),
            agent.clone(),
            engine.clone(),
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
        revision: 0,
        expires_at: DAY + 100,
    };
    client.transfer(&request);
    assert_eq!(token::Client::new(&env, &native).balance(&wallet), 990);
    assert_eq!(token::Client::new(&env, &native).balance(&recipient), 10);
    assert_eq!(client.state().spent_total, 10);
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
    let mut issued_grant = grant;
    issued_grant.asset = issued.clone();
    env.mock_all_auths_allowing_non_root_auth();
    let issued_wallet = env.register(
        XLM_POLICY_WASM,
        (
            owner,
            agent,
            engine,
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
    assert_eq!(issued_client.state().spent_total, 0);
    assert_eq!(
        token::Client::new(&env, &issued).balance(&issued_wallet),
        1000
    );
    assert_eq!(token::Client::new(&env, &issued).balance(&recipient), 0);
}

#[soroban_sdk::contractclient(name = "PreviousOdcClient")]
#[allow(dead_code)] // The generated client, rather than this declaration, is invoked.
trait PreviousOdcInterface {
    fn state(env: Env) -> State;
    fn transfer(env: Env, request: TransferRequest);
    fn upgrade(env: Env, new_wasm_hash: BytesN<32>, expected_revision: u64);
}

#[test]
fn actual_previous_odc_state_upgrade_retains_independent_owner_recovery() {
    const PREVIOUS_WASM: &[u8] =
        include_bytes!("../../../target/test-fixtures/odc_unbound_v1.wasm");
    let f = Fixture::new(true);
    let env = &f.env;
    let grant = f.client().state().grant;
    env.mock_all_auths_allowing_non_root_auth();
    let wallet = env.register(
        PREVIOUS_WASM,
        (f.owner.clone(), f.agent.clone(), f.engine.clone(), grant),
    );
    env.mock_all_auths();
    StellarAssetClient::new(env, &f.asset).mint(&wallet, &1000);
    let previous = PreviousOdcClient::new(env, &wallet);
    previous.transfer(&TransferRequest {
        recipient: f.recipient.clone(),
        amount: 10,
        nonce: 0,
        revision: 0,
        expires_at: DAY + 100,
    });
    let before = previous.state();
    assert_eq!(before.spent_total, 10);
    assert_eq!(before.nonce, 1);
    let new_hash = env.deployer().upload_contract_wasm(ODC_WASM);
    previous.upgrade(&new_hash, &before.revision);
    let current = OdcClient::new(env, &wallet);
    let mut expected = before;
    expected.revision += 1;
    assert_eq!(current.state(), expected);
    assert_eq!(current.try_policy_binding(), Err(Ok(Error::InvalidState)));
    let mut request = f.client().envelope(&f.request(1));
    request.nonce = expected.nonce;
    request.revision = expected.revision;
    assert_eq!(current.try_execute(&request), Err(Ok(Error::InvalidState)));
    current.recover(&f.owner, &20, &expected.revision);
    let recovered = current.state();
    assert_eq!(recovered.spent_total, 10);
    assert_eq!(recovered.nonce, 1);
    assert_eq!(recovered.revision, expected.revision + 1);
    assert_eq!(token::Client::new(env, &f.asset).balance(&f.owner), 20);
    assert_eq!(token::Client::new(env, &f.asset).balance(&wallet), 970);
}

// Real signatures and real host authorization exercise the token -> ODC hook.
fn x402_setup_compiled(compiled: bool) -> (Fixture, ed25519_dalek::SigningKey) {
    let f = Fixture::new(compiled);
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let pubkey = BytesN::from_array(&f.env, &key.verifying_key().to_bytes());
    let mut encoded = Bytes::from_slice(&f.env, &[0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0]);
    encoded.append(&pubkey.clone().into());
    let agent = Address::from_xdr(&f.env, &encoded).unwrap();
    let c = OdcClient::new(&f.env, &f.odc);
    c.set_agent(&agent, &c.state().revision);
    c.set_x402_signer(&Some(pubkey), &c.state().revision);
    (f, key)
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

#[test]
fn x402_signed_admission_shares_budget_and_replay_with_execute() {
    let (f, key) = x402_setup_compiled(false);
    let payload = BytesN::from_array(&f.env, &[42; 32]);
    let request = f.request(100);
    let execution = f.client().envelope(&request);
    let sig = x402_signed(&f, &key, execution.clone(), &payload);
    assert_eq!(
        f.env.try_invoke_contract_check_auth::<Error>(
            &f.odc,
            &payload,
            sig.into_val(&f.env),
            &x402_context(&f, 100)
        ),
        Ok(())
    );
    assert_eq!(f.client().state().spent_total, 100);
    assert_eq!(f.client().state().nonce, 1);
    assert!(
        OdcClient::new(&f.env, &f.odc)
            .try_execute(&execution)
            .is_err()
    );
    let next = f.client().envelope(&f.request(100));
    let sig = x402_signed(&f, &key, next, &payload);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                sig.into_val(&f.env),
                &x402_context(&f, 100)
            )
            .is_err()
    );
    assert_eq!(f.client().state().spent_total, 100);
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
    let c = OdcClient::new(&f.env, &f.odc);
    c.set_grant(&c.state().grant, &c.state().revision);
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
    assert_eq!(c.state().spent_total, 0);
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

#[test]
fn x402_real_token_hook_transfers_and_rolls_back_failed_token_effect() {
    x402_actual_effect(false);
    x402_actual_effect(true);
}

fn x402_actual_effect(compiled: bool) {
    let (f, key) = x402_setup_compiled(compiled);
    let auth = x402_host_entry(&f, &key, 50, 7);
    f.env.set_auths(&[auth]);
    token::Client::new(&f.env, &f.asset).transfer(&f.odc, &f.recipient, &50);
    assert_eq!(f.balance(&f.recipient), 50);
    assert_eq!(f.client().state().spent_total, 50);
    assert_eq!(f.client().state().calls, 1);
    // Native StellarAsset failure occurs after authorization (frozen recipient).
    f.env.mock_all_auths();
    StellarAssetClient::new(&f.env, &f.asset).set_authorized(&f.recipient, &false);
    let auth = x402_host_entry(&f, &key, 50, 8);
    f.env.set_auths(&[auth]);
    assert!(
        token::Client::new(&f.env, &f.asset)
            .try_transfer(&f.odc, &f.recipient, &50)
            .is_err()
    );
    assert_eq!(f.client().state().spent_total, 50);
    assert_eq!(f.client().state().calls, 1);
    assert_eq!(f.balance(&f.recipient), 50);
}

#[test]
fn x402_rejects_signed_invalid_requests_and_engine_veto() {
    let (f, key) = x402_setup_compiled(false);
    let payload = BytesN::from_array(&f.env, &[42; 32]);
    let valid = f.client().envelope(&f.request(50));
    let mut cases = std::vec::Vec::new();
    let mut bad = valid.clone();
    bad.nonce += 1;
    cases.push(bad);
    let mut bad = valid.clone();
    bad.revision += 1;
    cases.push(bad);
    let mut bad = valid.clone();
    bad.expires_at = f.env.ledger().timestamp();
    cases.push(bad);
    let mut bad = valid.clone();
    bad.policy_instance = BytesN::from_array(&f.env, &[9; 32]);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.operation_id = BytesN::from_array(&f.env, &[0; 32]);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.invocation.module_digest = BytesN::from_array(&f.env, &[9; 32]);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.invocation.argument_schema_digest = BytesN::from_array(&f.env, &[9; 32]);
    cases.push(bad);
    let mut bad = valid.clone();
    bad.invocation.entrypoint = Symbol::new(&f.env, "other");
    cases.push(bad);
    for execution in cases {
        let sig = x402_signed(&f, &key, execution, &payload);
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
        assert_eq!(f.client().state().spent_total, 0);
    }
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let sig = x402_signed(&f, &wrong, valid.clone(), &payload);
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
    let c = OdcClient::new(&f.env, &f.odc);
    for engine in [f.env.register(Deny, ()), f.env.register(Trap, ())] {
        c.set_engine(&engine, &c.state().revision);
        let sig = x402_signed(&f, &key, f.client().envelope(&f.request(50)), &payload);
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
        assert_eq!(c.state().spent_total, 0);
    }
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
    let c = OdcClient::new(&f.env, &f.odc);
    c.set_x402_signer(&None, &c.state().revision);
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
    c.set_x402_signer(
        &Some(BytesN::from_array(&f.env, &key.verifying_key().to_bytes())),
        &c.state().revision,
    );
    c.set_agent(&c.state().agent, &c.state().revision);
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
    assert_eq!(c.state().calls, 0);
}

#[test]
fn x402_execute_then_hook_replay_and_shared_daily_budget() {
    let (f, key) = x402_setup_compiled(false);
    let payload = BytesN::from_array(&f.env, &[42; 32]);
    let execution = f.client().envelope(&f.request(100));
    OdcClient::new(&f.env, &f.odc).execute(&execution);
    let sig = x402_signed(&f, &key, execution, &payload);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                sig.into_val(&f.env),
                &x402_context(&f, 100)
            )
            .is_err()
    );
    let sig = x402_signed(&f, &key, f.client().envelope(&f.request(100)), &payload);
    assert!(
        f.env
            .try_invoke_contract_check_auth::<Error>(
                &f.odc,
                &payload,
                sig.into_val(&f.env),
                &x402_context(&f, 100)
            )
            .is_err()
    );
    assert_eq!(f.client().state().spent_total, 100);
    assert_eq!(f.balance(&f.recipient), 100);
}
