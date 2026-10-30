//! Portability proof: the same authored source compiles under the host and Soroban backends and
//! yields identical pass values and errors on a shared vector set.
extern crate std;
use super::*;
use allowit::DAY;
use soroban_sdk::{Address, Bytes, testutils::Address as _};
use std::{format, string::String as Text, string::ToString, vec::Vec as List};

/// The authored policy compiled against the offchain host backend.
mod host_policy {
    use ::allowit::host as allowit;
    include!("../policy/policy.rs");
}
/// A policy that branches on the typed operation, compiled under both backends.
mod branch_onchain {
    include!("branch_policy.rs");
}
mod branch_host {
    use ::allowit::host as allowit;
    include!("branch_policy.rs");
}

/// Every canonical rule of one backend, in Grant field order.
macro_rules! rules {
    ($lib:path) => {{
        use $lib as lib;
        [
            lib::Rule::transaction_cap,
            lib::Rule::spent_cap,
            lib::Rule::day_spent_cap,
            lib::Rule::day_total_cap,
            lib::Rule::call_cap,
            lib::Rule::recipients,
            lib::Rule::tokens,
            lib::Rule::expiry,
        ]
    }};
}
/// Backend-neutral rule input. Addresses are indices into a shared address universe.
#[derive(Clone)]
struct Vector {
    caps: [Option<i128>; 4],
    call_cap: Option<u64>,
    recipients: Option<List<usize>>,
    tokens: Option<List<usize>>,
    expiry: Option<u64>,
    calls: u64,
    spent: i128,
    unpriced: bool,
    day: u64,
    day_spent: i128,
    day_total: i128,
    day_unpriced: bool,
    deposit: bool,
    asset: usize,
    recipient: usize,
    amount: i128,
    now: u64,
    expires_at: u64,
}
const ASSET: usize = 0;
const RECIPIENT: usize = 1;
const VAULT: usize = 2;
const OTHER: usize = 3;
const NOW: u64 = 2 * DAY + 100;

fn base() -> Vector {
    Vector {
        caps: [Some(100), Some(1000), Some(500), Some(600)],
        call_cap: Some(3),
        recipients: Some(std::vec![RECIPIENT, VAULT]),
        tokens: Some(std::vec![ASSET]),
        expiry: Some(NOW + 1000),
        calls: 1,
        spent: 45,
        unpriced: false,
        day: NOW / DAY,
        day_spent: 45,
        day_total: 43,
        day_unpriced: false,
        deposit: false,
        asset: ASSET,
        recipient: RECIPIENT,
        amount: 40,
        now: NOW,
        expires_at: NOW + 400,
    }
}

/// Every outcome a policy author can observe: the full policy, each rule and the preflight runner.
#[derive(Debug, PartialEq)]
struct Outcome {
    policy: Result<(), u32>,
    branch: Result<(), u32>,
    rules: List<Result<Text, u32>>,
    preflight: List<Result<(), u32>>,
}

macro_rules! outcome {
    ($lib:path, $policy:path, $branch:path, $ctx:expr, $index:expr) => {{
        use $lib as lib;
        let ctx = $ctx;
        let g = &ctx.grant;
        let code = |e: lib::Error| e as u32;
        Outcome {
            policy: $policy(&ctx).map_err(code),
            branch: $branch(&ctx).map_err(code),
            rules: std::vec![
                lib::transaction_cap(&ctx, &g.transaction_cap)
                    .map(|v| v.to_string())
                    .map_err(code),
                lib::spent_cap(&ctx, &g.spent_cap)
                    .map(|v| v.to_string())
                    .map_err(code),
                lib::day_spent_cap(&ctx, &g.day_spent_cap)
                    .map(|v| v.to_string())
                    .map_err(code),
                lib::day_total_cap(&ctx, &g.day_total_cap)
                    .map(|v| v.to_string())
                    .map_err(code),
                lib::call_cap(&ctx, &g.call_cap)
                    .map(|v| v.to_string())
                    .map_err(code),
                lib::recipients(&ctx, &g.recipients)
                    .map(|a| format!("@{}", $index(&a)))
                    .map_err(code),
                lib::tokens(&ctx, &g.tokens)
                    .map(|a| format!("@{}", $index(&a)))
                    .map_err(code),
                lib::expiry(&ctx, &g.expiry)
                    .map(|v| v.to_string())
                    .map_err(code),
            ],
            preflight: rules!($lib)
                .into_iter()
                .map(|rule| lib::preflight(&ctx, rule).map_err(code))
                .collect(),
        }
    }};
}

fn strkey(address: &Address) -> Text {
    let text = address.to_string();
    let mut bytes = std::vec![0u8; text.len() as usize];
    text.copy_into_slice(&mut bytes);
    Text::from_utf8(bytes).unwrap()
}

/// Shared address universe: Soroban addresses and their StrKey text for the host backend.
struct Universe {
    env: Env,
    onchain: List<Address>,
    host: List<Text>,
}
impl Universe {
    fn new() -> Self {
        let env = Env::default();
        let onchain: List<Address> = (0..4).map(|_| Address::generate(&env)).collect();
        let host = onchain.iter().map(strkey).collect();
        Self { env, onchain, host }
    }
    fn onchain(&self, v: &Vector) -> AllowitEnv {
        let list = |items: &Option<List<usize>>| {
            items.as_ref().map(|items| {
                let mut out = soroban_sdk::Vec::new(&self.env);
                for i in items {
                    out.push_back(self.onchain[*i].clone());
                }
                out
            })
        };
        AllowitEnv {
            grant: allowit::Grant {
                transaction_cap: v.caps[0],
                spent_cap: v.caps[1],
                day_spent_cap: v.caps[2],
                day_total_cap: v.caps[3],
                call_cap: v.call_cap,
                recipients: list(&v.recipients),
                tokens: list(&v.tokens),
                expiry: v.expiry,
            },
            state: allowit::AccountingHistory {
                calls: v.calls,
                spent: v.spent,
                unpriced: v.unpriced,
                day: v.day,
                day_spent: v.day_spent,
                day_total: v.day_total,
                day_unpriced: v.day_unpriced,
            },
            request: allowit::Request {
                operation: if v.deposit {
                    allowit::Operation::sep56_deposit
                } else {
                    allowit::Operation::sep41_transfer
                },
                asset: self.onchain[v.asset].clone(),
                recipient: self.onchain[v.recipient].clone(),
                amount: v.amount,
                now: v.now,
                expires_at: v.expires_at,
            },
        }
    }
    fn host(&self, v: &Vector) -> allowit::host::AllowitEnv {
        let list = |items: &Option<List<usize>>| {
            items
                .as_ref()
                .map(|items| items.iter().map(|i| self.host[*i].clone()).collect())
        };
        allowit::host::AllowitEnv {
            grant: allowit::host::Grant {
                transaction_cap: v.caps[0],
                spent_cap: v.caps[1],
                day_spent_cap: v.caps[2],
                day_total_cap: v.caps[3],
                call_cap: v.call_cap,
                recipients: list(&v.recipients),
                tokens: list(&v.tokens),
                expiry: v.expiry,
            },
            state: allowit::host::AccountingHistory {
                calls: v.calls,
                spent: v.spent,
                unpriced: v.unpriced,
                day: v.day,
                day_spent: v.day_spent,
                day_total: v.day_total,
                day_unpriced: v.day_unpriced,
            },
            request: allowit::host::Request {
                operation: if v.deposit {
                    allowit::host::Operation::sep56_deposit
                } else {
                    allowit::host::Operation::sep41_transfer
                },
                asset: self.host[v.asset].clone(),
                recipient: self.host[v.recipient].clone(),
                amount: v.amount,
                now: v.now,
                expires_at: v.expires_at,
            },
        }
    }
    /// Run one vector under both backends and require identical outcomes.
    fn run(&self, v: &Vector) -> Outcome {
        let onchain = outcome!(
            ::allowit::soroban,
            policy::execute,
            branch_onchain::execute,
            self.onchain(v),
            |a: &Address| self.onchain.iter().position(|x| x == a).unwrap()
        );
        let host = outcome!(
            ::allowit::host,
            host_policy::execute,
            branch_host::execute,
            self.host(v),
            |a: &Text| self.host.iter().position(|x| x == a).unwrap()
        );
        assert_eq!(onchain, host);
        onchain
    }
}

fn ok(values: [&str; 8]) -> List<Result<Text, u32>> {
    values.iter().map(|v| Ok(v.to_string())).collect()
}
fn all_preflight_ok() -> List<Result<(), u32>> {
    std::vec![Ok(()); 8]
}
use allowit::Error as E;

#[test]
fn same_source_has_identical_outcomes_on_host_and_soroban_backends() {
    let u = Universe::new();
    let mut checked = 0;
    let expect = |v: Vector, policy: Result<(), E>, rules: List<Result<Text, u32>>| {
        let o = u.run(&v);
        assert_eq!(o.policy, policy.map_err(|e| e as u32));
        assert_eq!(o.rules, rules);
        o
    };
    // Exact pass values.
    let o = expect(
        base(),
        Ok(()),
        ok(["60", "955", "455", "557", "2", "@1", "@0", "1000"]),
    );
    assert_eq!(o.preflight, all_preflight_ok());
    checked += 1;
    // Boundary equality leaves zero headroom and still passes.
    let mut v = base();
    v.caps = [Some(40), Some(45), Some(45), Some(43)];
    v.call_cap = Some(1);
    v.expiry = Some(v.expires_at);
    expect(v, Ok(()), ok(["0", "0", "0", "0", "0", "@1", "@0", "400"]));
    checked += 1;
    // Deposits name the vault as recipient.
    let mut v = base();
    v.deposit = true;
    v.recipient = VAULT;
    let o = u.run(&v);
    assert_eq!(o.policy, Ok(()));
    assert_eq!(o.branch, Ok(()));
    assert_eq!(o.rules[5], Ok("@2".to_string()));
    checked += 1;
    // Authored code beyond canonical calls branches on the typed operation on both backends.
    let mut v = base();
    v.caps[1] = None;
    assert_eq!(u.run(&v).branch, Ok(()));
    v.deposit = true;
    assert_eq!(u.run(&v).branch, Err(E::MissingGrant as u32));
    v.caps[1] = Some(44);
    assert_eq!(u.run(&v).branch, Err(E::SpentCapExceeded as u32));
    v.deposit = false;
    assert_eq!(u.run(&v).branch, Ok(()));
    checked += 1;
    // One more unit than each cap denies with that rule's error.
    let mut v = base();
    v.amount = 101;
    let o = u.run(&v);
    assert_eq!(o.policy, Err(E::TransactionCapExceeded as u32));
    assert_eq!(o.preflight[0], Err(E::TransactionCapExceeded as u32));
    let mut v = base();
    v.caps[1] = Some(44);
    assert_eq!(u.run(&v).policy, Err(E::SpentCapExceeded as u32));
    let mut v = base();
    v.caps[2] = Some(44);
    assert_eq!(u.run(&v).policy, Err(E::DaySpentCapExceeded as u32));
    let mut v = base();
    v.caps[3] = Some(42);
    assert_eq!(u.run(&v).policy, Err(E::DayTotalCapExceeded as u32));
    let mut v = base();
    v.call_cap = Some(0);
    assert_eq!(u.run(&v).policy, Err(E::CallCapExceeded as u32));
    checked += 5;
    // Unpriced and wrong-day accounting.
    let mut v = base();
    v.unpriced = true;
    let o = u.run(&v);
    assert_eq!(o.rules[1], Err(E::Unpriced as u32));
    assert_eq!(o.rules[2], Ok("455".to_string()));
    let mut v = base();
    v.day_unpriced = true;
    let o = u.run(&v);
    assert_eq!(o.rules[1], Ok("955".to_string()));
    assert_eq!(o.rules[2], Err(E::Unpriced as u32));
    assert_eq!(o.rules[3], Err(E::Unpriced as u32));
    // Only the daily caps read the day.
    let mut v = base();
    v.day -= 1;
    let o = u.run(&v);
    assert_eq!(o.rules[1], Ok("955".to_string()));
    for i in 2..4 {
        assert_eq!(o.rules[i], Err(E::InvalidState as u32));
    }
    checked += 3;
    // Empty and nonmatching allowlists.
    let mut v = base();
    v.recipients = Some(List::new());
    v.tokens = Some(List::new());
    let o = u.run(&v);
    assert_eq!(o.rules[5], Err(E::RecipientNotAllowed as u32));
    assert_eq!(o.rules[6], Err(E::TokenNotAllowed as u32));
    let mut v = base();
    v.recipient = OTHER;
    assert_eq!(u.run(&v).policy, Err(E::RecipientNotAllowed as u32));
    // Expiry and invalid parameters.
    let mut v = base();
    v.now = NOW + 1000;
    v.expires_at = NOW + 1001;
    v.day = v.now / DAY;
    assert_eq!(u.run(&v).policy, Err(E::Expired as u32));
    let mut v = base();
    v.caps[0] = Some(-1);
    assert_eq!(u.run(&v).policy, Err(E::InvalidParameter as u32));
    checked += 4;
    // An unset Grant field denies in the policy and rule, and is skipped only by preflight.
    for field in 0..8 {
        let mut v = base();
        match field {
            0..=3 => v.caps[field] = None,
            4 => v.call_cap = None,
            5 => v.recipients = None,
            6 => v.tokens = None,
            _ => v.expiry = None,
        }
        let o = u.run(&v);
        assert_eq!(o.policy, Err(E::MissingGrant as u32));
        assert_eq!(o.rules[field], Err(E::MissingGrant as u32));
        assert_eq!(o.preflight, all_preflight_ok());
        checked += 1;
    }
    assert_eq!(checked, 24);
}

#[test]
fn source_and_schema_bindings_match_their_exact_inputs() {
    let env = Env::default();
    let source = Bytes::from_slice(&env, include_bytes!("../policy/policy.rs"));
    assert_eq!(env.crypto().sha256(&source).to_array(), SOURCE_HASH);
    let schema = Bytes::from_slice(&env, allowit_wallet_protocol::ARGUMENT_SCHEMA_DESCRIPTOR);
    assert_eq!(
        env.crypto().sha256(&schema).to_array(),
        ARGUMENT_SCHEMA_HASH
    );
    let descriptor = core::str::from_utf8(allowit_wallet_protocol::ARGUMENT_SCHEMA_DESCRIPTOR);
    let operation = ADMITTED_OPERATION.replace("::", ".");
    assert!(descriptor.unwrap().contains(&operation));
}
