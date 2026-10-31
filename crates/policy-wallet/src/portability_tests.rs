//! Four-target portability test. One shared vector set (`scripts/policy-vectors.rs`) runs through:
//!
//! 1. the host backend: `scripts/policy-smoke.rs` compiled with plain `rustc` against `allowit`
//!    with only the `std` feature, so a policy that names `soroban_sdk` or a wallet crate fails;
//! 2. `AllowitCustomPolicy`: the Soroban backend of the same sources, then the real custom Wasm,
//!    and the `test-catching` fixture Wasm, whose policy catches a daily cap error, continues and
//!    writes its own state key;
//! 3. `AllowitCommonPolicyEngine`: the real standard Wasm with the policy's leading-rule prefix;
//! 4. `AllowitSimplePolicyEngine`: the real simple Wasm, which has no rules.
//!
//! Host and Soroban outcomes must be identical on every pass value, error and post-flight state.
//! Each vector holds the current state before the operation. The custom contract must return the
//! mapped policy result, and the catching fixture the mapped catching result. The standard
//! contract must return the mapped first prefix preflight error, which skips unset Grant fields.
//! The simple contract runs no rules. Every contract then returns the shared post-flight result
//! and stores exactly the post-flight state that the host computed. Kernel violations reject
//! identically in every contract.
//!
//! A writing suffix on the standard tiers: the server keeps the suffix's own keys offchain and
//! builds `ctx.state` with `allowit::offchain_state`, so Common and Simple approve exactly the
//! operations that the catching custom contract approves.
extern crate std;
use super::tests::{CATCHING, COMMON, CUSTOM, Fixture, SIMPLE};
use super::*;
use allowit::{AllowitError, AllowitStandardState};
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
const ERRORS: [AllowitError; 14] = [
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
    AllowitError::Overflow,
    AllowitError::Unsupported,
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
/// The current state map of a vector, with the catching policy's key when set.
fn state_map(env: &Env, v: &Vector) -> Map<Symbol, Val> {
    let mut state = Map::new(env);
    let s = AllowitStandardState {
        calls: v.calls,
        spent: v.spent,
        unpriced: v.unpriced,
        day: v.day,
        day_spent: v.day_spent,
        day_total: v.day_total,
        day_unpriced: v.day_unpriced,
    };
    s.write(env, &mut state).unwrap();
    if let Some(over) = v.over {
        state.set(Symbol::new(env, vectors::OVER), over.into_val(env));
    }
    state
}
/// A state map as `vectors::state_line`.
fn line(env: &Env, state: &Map<Symbol, Val>) -> Text {
    let s = AllowitStandardState::read(env, state).unwrap();
    let over = state
        .get(Symbol::new(env, vectors::OVER))
        .map(|raw| u64::try_from_val(env, &raw).unwrap());
    vectors::state_line(
        s.calls,
        s.spent,
        s.unpriced,
        s.day,
        s.day_spent,
        s.day_total,
        s.day_unpriced,
        over,
    )
}
fn context(env: &Env, universe: &[Address], v: &Vector) -> AllowitContext {
    AllowitContext {
        env: env.clone(),
        grant: grant(env, universe, v),
        state: state_map(env, v),
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
            spent_units: v.spent_units,
            gas_units: v.gas_units,
            unpriced: !v.priced,
        },
    }
}
/// Soroban backend outcome, inside a contract so policy writes have temporary storage.
fn soroban_outcome(env: &Env, contract: &Address, universe: &[Address], v: &Vector) -> Outcome {
    env.as_contract(contract, || {
        let c = context(env, universe, v);
        let g = &c.grant;
        let code = |e: AllowitError| e as u32;
        let index = |a: Address| format!("@{}", universe.iter().position(|x| *x == a).unwrap());
        let next = || {
            allowit::post_flight(&c)
                .map(|state| line(env, &state))
                .map_err(code)
        };
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
        let policy = sample::execute(&c).map_err(code);
        let branch = branch::execute(&c).map_err(code);
        let plain = next();
        // The catching policy may write; post-flight consumes the writes in either case.
        let catching = catching::execute(&c).map_err(code);
        let catching_next = next();
        Outcome {
            policy,
            branch,
            catching,
            rules,
            preflight,
            next: plain,
            catching_next: catching.and(catching_next),
        }
    })
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

/// Whether the kernel and owner configuration can produce the vector: a transfer of the installed
/// asset whose expense bounds, when priced, attest principal plus gas.
fn realizable(v: &Vector) -> bool {
    let cost = if v.priced {
        v.gas_units >= 0 && v.spent_units == v.amount + v.gas_units
    } else {
        v.spent_units == 0 && v.gas_units == 0
    };
    !v.deposit
        && v.asset == vectors::ASSET
        && v.amount > 0
        && v.expires_at > v.now
        && cost
        && v.caps.iter().flatten().all(|cap| *cap >= 0)
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
    /// Deploy the tier's Wasm, fund it and bind Common to the sample policy's prefix.
    fn new(tier: Tier) -> Self {
        let f = Fixture::new(Self::wasm(tier), false);
        f.env.mock_all_auths();
        StellarAssetClient::new(&f.env, &f.asset).mint(&f.wallet, &1_000_000);
        f.env.mock_auths(&[]);
        let mut universe = List::from([f.asset.clone(), f.recipient.clone()]);
        while universe.len() < vectors::ADDRESSES {
            universe.push(Address::generate(&f.env));
        }
        let wallet = Self {
            f,
            tier,
            universe,
            operations: core::cell::Cell::new(0),
        };
        if tier == Tier::Common {
            wallet.bind(&sample_prefix());
        }
        wallet
    }
    /// The deployed Wasm of a tier.
    fn wasm(tier: Tier) -> &'static [u8] {
        match tier {
            Tier::Custom => CUSTOM,
            Tier::Common => COMMON,
            Tier::Simple => SIMPLE,
            Tier::Catching => CATCHING,
        }
    }
    /// Bind the standard contract to an authored policy's leading-rule prefix.
    fn bind(&self, prefix: &[AllowitRule]) {
        let env = &self.f.env;
        let mut rules = Vec::new(env);
        for rule in prefix {
            rules.push_back(*rule);
        }
        let module = env
            .crypto()
            .sha256(&Bytes::from_slice(env, Self::wasm(self.tier)));
        let digest = standard_prefix_digest(
            env,
            &Symbol::new(env, "common_policy_engine"),
            &module.to_bytes(),
            &self.f.asset,
            &rules,
        );
        env.as_contract(&self.f.wallet, || {
            let mut state = state(env).unwrap();
            state.rules = rules;
            state.source_digest = digest;
            store(env, &state);
        });
    }
    /// Install the vector's Grant and current state, and move the ledger to the request time.
    /// The owner can change Grant values without code redeployment.
    fn seed(&self, v: &Vector, paused: bool) {
        let env = &self.f.env;
        env.ledger().with_mut(|l| l.timestamp = v.now);
        env.as_contract(&self.f.wallet, || {
            let mut s = state(env).unwrap();
            s.grant = grant(env, &self.universe, v);
            s.policy_state = state_map(env, v);
            s.paused = paused;
            store(env, &s);
        });
    }
    fn request(&self, v: &Vector) -> AllowitExecutionRequest {
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
            gas_units: v.gas_units,
            conversion_units: 0,
            spent_units: v.spent_units,
            max_fee_stroops: u32::try_from(v.gas_units).unwrap(),
            observed_ledger: 1,
            day: v.now / 86_400,
        };
        AllowitExecutionRequest {
            source_hash: if matches!(self.tier, Tier::Custom | Tier::Catching) {
                b.source_digest.clone()
            } else {
                BytesN::from_array(env, &[9; 32])
            },
            expense: v.priced.then(|| expense.to_xdr(env)),
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
    // Realized vectors where the catching policy caught a rule error and the operation succeeded.
    let mut caught = List::new();
    for (v, host) in all.iter().zip(&host) {
        // 1 and 2: the host smoke and the Soroban backend agree on every pass value, error and
        // post-flight state.
        let outcome = soroban_outcome(&custom.f.env, &custom.f.wallet, &custom.universe, v);
        assert_eq!(*host, outcome.line(v.name));
        if !realizable(v) {
            continue;
        }
        realized += 1;
        let next = outcome.next.clone().map(|_| ());
        let first_prefix_error = prefix
            .iter()
            .map(|rule| outcome.preflight[RULES.iter().position(|r| r == rule).unwrap()])
            .find(Result::is_err);
        let expected = |tier: Tier| {
            match tier {
                Tier::Custom => outcome.policy.and(next),
                Tier::Common => first_prefix_error.unwrap_or(Ok(())).and(next),
                Tier::Simple => next,
                Tier::Catching => outcome.catching_next.clone().map(|_| ()),
            }
            .map_err(wallet_error)
        };
        let unset = v.caps.contains(&None)
            || v.call_cap.is_none()
            || v.recipients.is_none()
            || v.tokens.is_none()
            || v.expiry.is_none();
        if !unset {
            assert_eq!(expected(Tier::Common), expected(Tier::Custom), "{}", v.name);
        }
        if outcome.catching.is_ok() && outcome.policy.is_err() {
            caught.push(v.name);
        }
        for wallet in &wallets {
            wallet.seed(v, false);
            let result = wallet.execute(&wallet.request(v));
            assert_eq!(
                result,
                expected(wallet.tier),
                "{} {:?}",
                v.name,
                wallet.tier
            );
            // The contract stored exactly the post-flight state that the host computed.
            if result.is_ok() {
                let stored = line(&wallet.f.env, &wallet.f.client().policy_state());
                let want = match wallet.tier {
                    Tier::Catching => outcome.catching_next.clone(),
                    _ => outcome.next.clone(),
                };
                assert_eq!(Ok(stored), want, "{} {:?}", v.name, wallet.tier);
            }
        }
    }
    assert_eq!(realized, 33);
    // The deployed catching Wasm let these continue after a caught rule error and wrote its key.
    for name in ["over_day_spent_cap", "over_day_spent_cap_counted_once"] {
        assert!(caught.contains(&name), "{name} {caught:?}");
    }
}

#[test]
fn kernel_violations_reject_identically_in_every_contract() {
    use AllowitWalletError as W;
    let v = vectors::base();
    assert!(realizable(&v));
    for wallet in TIERS.map(Wallet::new) {
        let env = &wallet.f.env;
        let tier = wallet.tier;
        let reject = |change: &dyn Fn(&mut AllowitExecutionRequest), paused: bool| {
            wallet.seed(&v, paused);
            let mut e = wallet.request(&v);
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
        wallet.seed(&v, false);
        let e = wallet.request(&v);
        assert_eq!(wallet.execute(&e), Ok(()), "{tier:?}");
        let mut replay = wallet.request(&v);
        replay.operation_id = e.operation_id;
        assert_eq!(wallet.execute(&replay), Err(W::Replay as u32), "{tier:?}");
    }
}

/// Simple and Common store only standard keys: the catching suffix's own key never reaches the
/// chain. The server keeps it and builds `ctx.state` with `allowit::offchain_state`, so the
/// standard tiers allow exactly the two caught daily cap errors that the custom contract allows.
#[test]
fn standard_tier_server_keeps_suffix_writes_and_matches_the_custom_contract() {
    let mut v = vectors::base();
    v.caps[2] = Some(44);
    let custom = Wallet::new(Tier::Catching);
    let common = Wallet::new(Tier::Common);
    // The catching policy's prefix is its leading `recipients` call.
    common.bind(&[AllowitRule::recipients]);
    let simple = Wallet::new(Tier::Simple);
    let mut want = List::new();
    custom.seed(&v, false);
    for _ in 0..3 {
        let result = custom.execute(&custom.request(&v));
        let stored = line(&custom.f.env, &custom.f.client().policy_state());
        want.push(result.map(|()| stored));
    }
    let denied = Err(wallet_error(AllowitError::DaySpentCapExceeded as u32));
    assert!(
        want[0].is_ok() && want[1].is_ok() && want[2] == denied,
        "{want:?}"
    );
    for wallet in [&common, &simple] {
        let env = &wallet.f.env;
        wallet.seed(&v, false);
        // The server's view: the state map of its last approved evaluation.
        let mut kept = Map::new(env);
        // Evaluate the full catching policy on the server's `ctx.state`, as the server would.
        let evaluate = |state: Map<Symbol, Val>| {
            env.as_contract(&wallet.f.wallet, || {
                let mut c = context(env, &wallet.universe, &v);
                c.state = state;
                allowit::evaluate(&c, catching::execute).map_err(|e| wallet_error(e as u32))
            })
        };
        for (i, want) in want.iter().enumerate() {
            let chain = wallet.f.client().policy_state();
            // Danger: from chain state alone the suffix never sees its count and approves the third.
            assert!(evaluate(chain.clone()).is_ok(), "{i} {:?}", wallet.tier);
            let got = evaluate(allowit::offchain_state(&kept, &chain)).and_then(|next| {
                // The server signs only an approved evaluation; the wallet then agrees.
                wallet.execute(&wallet.request(&v))?;
                let after = wallet.f.client().policy_state();
                // The chain stored the host's standard keys; only the suffix's key stays offchain.
                assert_eq!(allowit::offchain_state(&next, &after), next, "{i}");
                assert!(!after.contains_key(Symbol::new(env, vectors::OVER)), "{i}");
                kept = next;
                Ok(line(env, &kept))
            });
            assert_eq!(got, *want, "{i} {:?}", wallet.tier);
        }
    }
}
