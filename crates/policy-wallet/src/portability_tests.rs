//! Four-target portability test. One shared vector set (`scripts/policy-vectors.rs`) runs through:
//!
//! 1. the host backend: `scripts/policy-smoke.rs` compiled with plain `rustc` against `allowit`
//!    with only the `std` feature, so a policy that names `soroban_sdk` or a wallet crate fails;
//! 2. `AllowitCustomPolicy`: the Soroban backend of the same sources, then the real custom Wasm,
//!    and the `test-catching` fixture Wasm, which compiles the catching policy, so the onchain
//!    rule-failure record must deny the failures that the policy catches;
//! 3. `AllowitCommonPolicyEngine`: the real standard Wasm with the policy's leading-rule prefix;
//! 4. `AllowitSimplePolicyEngine`: the real simple Wasm, which has no rules.
//!
//! Host and Soroban outcomes must be identical on every pass value and error. The custom contract
//! must return the mapped policy result, and the catching fixture the mapped catching result. The standard contract must return the mapped first
//! prefix preflight error, which skips unset Grant fields. The simple contract must accept every
//! vector that the kernel accepts. Kernel violations reject identically in every contract.
extern crate std;
use super::tests::{CATCHING, COMMON, CUSTOM, Fixture, SIMPLE};
use super::*;
use allowit::AllowitError;
use allowit_wallet_protocol::AllowitPolicyInvocation;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::StellarAssetClient,
};
use std::{
    format,
    path::Path,
    process::Command,
    string::{String as Text, ToString},
    vec::Vec as List,
};

#[path = "../../custom-policy/src/branch_policy.rs"]
mod branch;
#[path = "../../custom-policy/src/catching_policy.rs"]
mod catching;
#[path = "../../custom-policy/policy/policy.rs"]
mod sample;
mod vectors {
    use super::std::{self, format, string::String, vec, vec::Vec};
    include!("../../../scripts/policy-vectors.rs");
}
use vectors::{Outcome, Vector};

/// Every canonical rule in Grant field order.
const RULES: [AllowitRule; 8] = [
    AllowitRule::transaction_cap,
    AllowitRule::spent_cap,
    AllowitRule::day_spent_cap,
    AllowitRule::day_total_cap,
    AllowitRule::call_cap,
    AllowitRule::recipients,
    AllowitRule::tokens,
    AllowitRule::expiry,
];
/// Every rule error, indexed by its code minus one.
const ERRORS: [AllowitError; 12] = [
    AllowitError::MissingGrant,
    AllowitError::TransactionCapExceeded,
    AllowitError::SpentCapExceeded,
    AllowitError::DaySpentCapExceeded,
    AllowitError::DayTotalCapExceeded,
    AllowitError::CallCapExceeded,
    AllowitError::RecipientNotAllowed,
    AllowitError::TokenNotAllowed,
    AllowitError::Expired,
    AllowitError::Unpriced,
    AllowitError::InvalidParameter,
    AllowitError::InvalidState,
];
/// The wallet error of a rule error code.
fn wallet_error(code: u32) -> u32 {
    let error = ERRORS[code as usize - 1];
    assert_eq!(error as u32, code);
    AllowitWalletError::from(error) as u32
}

/// Build the host smoke with plain `rustc` against `allowit` with only the `std` feature, run it
/// and return its vector lines.
fn host_lines() -> List<Text> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = root
        .join("target/policy-smoke")
        .join(std::process::id().to_string());
    std::fs::create_dir_all(&out).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let lib = out.join("liballowit.rlib");
    let bin = out.join("policy-smoke");
    let run = |command: &mut Command| {
        let output = command.current_dir(&root).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            Text::from_utf8_lossy(&output.stdout),
            Text::from_utf8_lossy(&output.stderr)
        );
        Text::from_utf8(output.stdout).unwrap()
    };
    // Overflow checks are explicit, as in the contract release profile and the offchain server.
    run(Command::new(&rustc)
        .args([
            "--edition=2024",
            "-Coverflow-checks=on",
            "--crate-type=rlib",
            "--crate-name=allowit",
        ])
        .args([
            "--cfg",
            "feature=\"std\"",
            "crates/allowit/src/lib.rs",
            "-o",
        ])
        .arg(&lib));
    run(Command::new(&rustc)
        .args([
            "--edition=2024",
            "-Coverflow-checks=on",
            "--test",
            "--extern",
        ])
        .arg(format!("allowit={}", lib.display()))
        .args(["scripts/policy-smoke.rs", "-o"])
        .arg(&bin));
    let stdout = run(Command::new(&bin).args([
        "vectors_print_host_outcomes",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]));
    std::fs::remove_dir_all(&out).unwrap();
    // libtest prints the test name without a newline before the first captured line.
    stdout
        .lines()
        .filter_map(|line| line.find("vector ").map(|i| line[i..].to_string()))
        .collect()
}

fn list(env: &Env, universe: &[Address], items: &Option<List<usize>>) -> Option<Vec<Address>> {
    items.as_ref().map(|items| {
        let mut out = Vec::new(env);
        for i in items {
            out.push_back(universe[*i].clone());
        }
        out
    })
}
fn grant(env: &Env, universe: &[Address], v: &Vector) -> AllowitGrant {
    AllowitGrant {
        transaction_cap: v.caps[0],
        spent_cap: v.caps[1],
        day_spent_cap: v.caps[2],
        day_total_cap: v.caps[3],
        call_cap: v.call_cap,
        recipients: list(env, universe, &v.recipients),
        tokens: list(env, universe, &v.tokens),
        expiry: v.expiry,
    }
}
fn history(v: &Vector) -> AllowitAccountingHistory {
    AllowitAccountingHistory {
        calls: v.calls,
        spent: v.spent,
        unpriced: v.unpriced,
        day: v.day,
        day_spent: v.day_spent,
        day_total: v.day_total,
        day_unpriced: v.day_unpriced,
    }
}
fn context(env: &Env, universe: &[Address], v: &Vector) -> AllowitContext {
    AllowitContext {
        env: env.clone(),
        grant: grant(env, universe, v),
        state: history(v),
        request: AllowitRequest {
            operation: if v.deposit {
                AllowitOperation::sep56_deposit
            } else {
                AllowitOperation::sep41_transfer
            },
            asset: universe[v.asset].clone(),
            recipient: universe[v.recipient].clone(),
            amount: v.amount,
            now: v.now,
            expires_at: v.expires_at,
        },
    }
}
/// Soroban backend outcome. Each policy run reads only its own rule failures.
fn soroban_outcome(env: &Env, universe: &[Address], v: &Vector) -> Outcome {
    let c = context(env, universe, v);
    let g = &c.grant;
    let code = |e: AllowitError| e as u32;
    let index = |a: Address| format!("@{}", universe.iter().position(|x| *x == a).unwrap());
    let run =
        |execute: fn(&AllowitContext) -> allowit::Result| allowit::run(&c, execute).map_err(code);
    let rules: List<Result<Text, u32>> = [
        allowit::transaction_cap(&c, &g.transaction_cap).map(|v| v.to_string()),
        allowit::spent_cap(&c, &g.spent_cap).map(|v| v.to_string()),
        allowit::day_spent_cap(&c, &g.day_spent_cap).map(|v| v.to_string()),
        allowit::day_total_cap(&c, &g.day_total_cap).map(|v| v.to_string()),
        allowit::call_cap(&c, &g.call_cap).map(|v| v.to_string()),
        allowit::recipients(&c, &g.recipients).map(index),
        allowit::tokens(&c, &g.tokens).map(index),
        allowit::expiry(&c, &g.expiry).map(|v| v.to_string()),
    ]
    .into_iter()
    .map(|r| r.map_err(code))
    .collect();
    let preflight = RULES
        .into_iter()
        .map(|rule| allowit::preflight(&c, rule).map_err(code))
        .collect();
    Outcome {
        policy: run(sample::execute),
        branch: run(branch::execute),
        catching: run(catching::execute),
        rules,
        preflight,
    }
}

/// The leading canonical calls of the sample policy, as `scripts/policy_source.py` derives them
/// for the standard contract.
fn sample_prefix() -> List<AllowitRule> {
    let source = include_str!("../../custom-policy/policy/policy.rs");
    let (_, body) = source
        .split_once("pub fn execute(ctx: &AllowitContext) -> allowit::Result {")
        .unwrap();
    let mut rules = List::new();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let call = line
            .strip_prefix("allowit::")
            .and_then(|call| call.strip_suffix(")?;"))
            .and_then(|call| call.split_once("(ctx, &ctx.grant."));
        let Some(rule) = call.and_then(|(rule, field)| {
            let i = RULES.iter().position(|r| std::format!("{r:?}") == rule)?;
            (rule == field).then_some(RULES[i])
        }) else {
            break;
        };
        rules.push(rule);
    }
    rules
}

/// Wallet history before the operation, and whether the operation carries expense bounds, such
/// that the kernel proposes exactly the vector's history. `None` when the kernel or owner
/// configuration cannot produce the vector.
fn kernel_input(v: &Vector) -> Option<(AllowitAccountingHistory, bool)> {
    let priced = !v.day_unpriced;
    let gross = |value: i128| (value >= 0).then_some(value);
    let spent = |value: i128| gross(if priced { value - v.amount } else { value });
    let realizable = !v.deposit
        && v.asset == vectors::ASSET
        && v.amount > 0
        && v.expires_at > v.now
        && v.day == v.now / 86_400
        && (priced || v.unpriced)
        && v.caps.iter().flatten().all(|cap| *cap >= 0);
    let prior = AllowitAccountingHistory {
        calls: v.calls.checked_sub(1)?,
        spent: spent(v.spent)?,
        unpriced: v.unpriced && priced,
        day: v.day,
        day_spent: spent(v.day_spent)?,
        day_total: gross(v.day_total - v.amount)?,
        day_unpriced: false,
    };
    realizable.then_some((prior, priced))
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tier {
    Custom,
    Common,
    Simple,
    /// The custom contract compiled with the catching policy.
    Catching,
}
/// Every deployed contract that the vectors run through.
const TIERS: [Tier; 4] = [Tier::Custom, Tier::Common, Tier::Simple, Tier::Catching];
/// One deployed wallet Wasm and its address universe.
struct Wallet {
    f: Fixture,
    tier: Tier,
    universe: List<Address>,
    operations: core::cell::Cell<u64>,
}
impl Wallet {
    fn new(tier: Tier) -> Self {
        let wasm = match tier {
            Tier::Custom => CUSTOM,
            Tier::Common => COMMON,
            Tier::Simple => SIMPLE,
            Tier::Catching => CATCHING,
        };
        let f = Fixture::new(wasm, false);
        f.env.mock_all_auths();
        StellarAssetClient::new(&f.env, &f.asset).mint(&f.wallet, &1_000_000);
        f.env.mock_auths(&[]);
        let mut universe = List::from([f.asset.clone(), f.recipient.clone()]);
        while universe.len() < vectors::ADDRESSES {
            universe.push(Address::generate(&f.env));
        }
        if tier == Tier::Common {
            // Bind the standard contract to the sample policy's prefix.
            let mut rules = Vec::new(&f.env);
            for rule in sample_prefix() {
                rules.push_back(rule);
            }
            let module = f.env.crypto().sha256(&Bytes::from_slice(&f.env, wasm));
            let digest = standard_prefix_digest(
                &f.env,
                &Symbol::new(&f.env, "common_policy_engine"),
                &module.to_bytes(),
                &f.asset,
                &rules,
            );
            f.env.as_contract(&f.wallet, || {
                let mut state = state(&f.env).unwrap();
                state.rules = rules;
                state.source_digest = digest;
                store(&f.env, &state);
            });
        }
        Self {
            f,
            tier,
            universe,
            operations: core::cell::Cell::new(0),
        }
    }
    /// Install the vector's Grant and the prior history, and move the ledger to the request time.
    /// The owner can change Grant values without code redeployment.
    fn seed(&self, v: &Vector, prior: &AllowitAccountingHistory, paused: bool) {
        let env = &self.f.env;
        env.ledger().with_mut(|l| l.timestamp = v.now);
        env.as_contract(&self.f.wallet, || {
            let mut s = state(env).unwrap();
            s.grant = grant(env, &self.universe, v);
            s.history = prior.clone();
            s.paused = paused;
            store(env, &s);
        });
    }
    fn request(&self, v: &Vector, priced: bool) -> AllowitExecutionRequest {
        let env = &self.f.env;
        let s = self.f.client().state();
        let b = self.f.client().policy_binding();
        let operation = self.operations.get() + 1;
        self.operations.set(operation);
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&operation.to_be_bytes());
        let expense = AllowitExpenseBounds {
            asset: self.f.asset.clone(),
            decimals: 7,
            gas_units: 0,
            conversion_units: 0,
            spent_units: v.amount,
            max_fee_stroops: 0,
            observed_ledger: 1,
            day: v.now / 86_400,
        };
        AllowitExecutionRequest {
            source_hash: if matches!(self.tier, Tier::Custom | Tier::Catching) {
                b.source_digest.clone()
            } else {
                BytesN::from_array(env, &[9; 32])
            },
            expense: priced.then(|| expense.to_xdr(env)),
            policy_instance: b.policy_instance,
            operation_id: BytesN::from_array(env, &id),
            nonce: s.nonce,
            deployment_version: s.deployment_version,
            expires_at: v.expires_at,
            invocation: AllowitPolicyInvocation {
                module_digest: b.module_digest,
                entrypoint: b.entrypoint,
                argument_schema_digest: b.argument_schema_digest,
                arguments: AllowitSep41TransferArgs {
                    token: self.universe[v.asset].clone(),
                    from: self.f.wallet.clone(),
                    to: self.universe[v.recipient].clone(),
                    amount: v.amount,
                }
                .to_xdr(env),
            },
        }
    }
    fn execute(&self, e: &AllowitExecutionRequest) -> Result<(), u32> {
        let f = &self.f;
        f.auth(
            &[&f.agent, &f.server],
            "execute",
            (e.clone(),).into_val(&f.env),
        );
        match f.client().try_execute(e) {
            Ok(Ok(_)) => Ok(()),
            Err(Ok(error)) => Err(error as u32),
            other => panic!("{:?} {:?}", self.tier, other.is_ok()),
        }
    }
}

#[test]
fn one_vector_set_has_matching_outcomes_on_host_custom_standard_and_simple() {
    let all = vectors::vectors();
    let host = host_lines();
    assert_eq!(host.len(), all.len());
    let wallets = TIERS.map(Wallet::new);
    let custom = &wallets[0];
    let prefix = sample_prefix();
    assert_eq!(prefix, RULES);
    let mut realized = 0;
    // Realized vectors whose rule failure the catching policy catches and the record denies.
    let mut caught = List::new();
    for (v, host) in all.iter().zip(&host) {
        // 1 and 2: the host smoke and the Soroban backend agree on every pass value and error.
        let outcome = soroban_outcome(&custom.f.env, &custom.universe, v);
        assert_eq!(*host, outcome.line(v.name));
        let Some((prior, priced)) = kernel_input(v) else {
            continue;
        };
        realized += 1;
        let expected_custom = outcome.policy.map_err(wallet_error);
        let expected_catching = outcome.catching.map_err(wallet_error);
        let direct = catching::execute(&context(&custom.f.env, &custom.universe, v));
        if direct.is_ok() && outcome.catching.is_err() {
            caught.push(v.name);
        }
        let first_prefix_error = prefix
            .iter()
            .map(|rule| outcome.preflight[RULES.iter().position(|r| r == rule).unwrap()])
            .find(Result::is_err);
        let expected_common = first_prefix_error.unwrap_or(Ok(())).map_err(wallet_error);
        let unset = v.caps.contains(&None)
            || v.call_cap.is_none()
            || v.recipients.is_none()
            || v.tokens.is_none()
            || v.expiry.is_none();
        if !unset {
            assert_eq!(expected_common, expected_custom, "{}", v.name);
        }
        for wallet in &wallets {
            wallet.seed(v, &prior, false);
            let result = wallet.execute(&wallet.request(v, priced));
            let expected = match wallet.tier {
                Tier::Custom => expected_custom,
                Tier::Common => expected_common,
                Tier::Simple => Ok(()),
                Tier::Catching => expected_catching,
            };
            assert_eq!(result, expected, "{} {:?}", v.name, wallet.tier);
            // The kernel proposed exactly the history that the host evaluated.
            if result.is_ok() {
                assert_eq!(wallet.f.client().state().history, history(v), "{}", v.name);
            }
        }
    }
    assert_eq!(realized, 24);
    // The deployed catching Wasm denied these only through the onchain rule-failure record.
    for name in ["over_spent_cap", "over_day_spent_cap"] {
        assert!(caught.contains(&name), "{name} {caught:?}");
    }
}

#[test]
fn kernel_violations_reject_identically_in_every_contract() {
    use AllowitWalletError as W;
    let v = vectors::base();
    let (prior, _) = kernel_input(&v).unwrap();
    for wallet in TIERS.map(Wallet::new) {
        let env = &wallet.f.env;
        let tier = wallet.tier;
        let reject = |change: &dyn Fn(&mut AllowitExecutionRequest), paused: bool| {
            wallet.seed(&v, &prior, paused);
            let mut e = wallet.request(&v, true);
            change(&mut e);
            wallet.execute(&e)
        };
        let transfer = |e: &mut AllowitExecutionRequest,
                        edit: &dyn Fn(&mut AllowitSep41TransferArgs)| {
            let mut args =
                AllowitSep41TransferArgs::from_xdr(env, &e.invocation.arguments).unwrap();
            edit(&mut args);
            e.invocation.arguments = args.to_xdr(env);
        };
        let other = wallet.universe[vectors::OTHER].clone();
        let asset = |e: &mut AllowitExecutionRequest| transfer(e, &|a| a.token = other.clone());
        let to_self =
            |e: &mut AllowitExecutionRequest| transfer(e, &|a| a.to = wallet.f.wallet.clone());
        let expired = |e: &mut AllowitExecutionRequest| e.expires_at = v.now;
        let stale = |e: &mut AllowitExecutionRequest| e.nonce += 1;
        assert_eq!(
            reject(&asset, false),
            Err(W::InvalidInvocation as u32),
            "{tier:?}"
        );
        assert_eq!(
            reject(&to_self, false),
            Err(W::InvalidRecipient as u32),
            "{tier:?}"
        );
        assert_eq!(reject(&expired, false), Err(W::Expired as u32), "{tier:?}");
        assert_eq!(
            reject(&stale, false),
            Err(W::StaleRequest as u32),
            "{tier:?}"
        );
        assert_eq!(reject(&|_| {}, true), Err(W::Paused as u32), "{tier:?}");
        // The same request passes, then its single-use operation ID rejects.
        wallet.seed(&v, &prior, false);
        let e = wallet.request(&v, true);
        assert_eq!(wallet.execute(&e), Ok(()), "{tier:?}");
        let mut replay = wallet.request(&v, true);
        replay.operation_id = e.operation_id;
        assert_eq!(wallet.execute(&replay), Err(W::Replay as u32), "{tier:?}");
    }
}
