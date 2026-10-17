extern crate std;

use super::*;
use soroban_sdk::{
    IntoVal, contract, contractimpl,
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
        let args = (owner.clone(), agent.clone(), engine.clone(), grant);
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
    fn client(&self) -> OdcClient<'_> {
        OdcClient::new(&self.env, &self.odc)
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
    assert_eq!(c.try_transfer(&first), Err(Ok(Error::StaleRequest)));
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
            fn_name: "transfer",
            args: (req.clone(),).into_val(&f.env),
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
        (owner_two.clone(), agent_two, shared_engine.clone(), grant),
    );
    env.mock_all_auths();
    StellarAssetClient::new(env, &f.asset).mint(&odc_two, &1_000);
    let second = OdcClient::new(env, &odc_two);
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
                (owner, agent, engine, grant),
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
    let args: soroban_sdk::Vec<soroban_sdk::Val> = (request.clone(),).into_val(&f.env);
    f.env.mock_auths(&[MockAuth {
        address: &f.agent,
        invoke: &MockAuthInvoke {
            contract: &f.odc,
            fn_name: "transfer",
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
                    soroban_sdk::Symbol::new(&f.env, "transfer"),
                    args,
                )),
                sub_invocations: std::vec![],
            },
        )]
    );
    assert_eq!(f.balance(&f.recipient), 10);
    assert_eq!(f.client().state().spent_total, 10);
}
