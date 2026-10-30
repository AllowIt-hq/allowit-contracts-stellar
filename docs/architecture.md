# Policy wallet engines

Wallets keep one immutable underlying Stellar Asset Contract (SAC). The owner selects code, agent,
independent server signer and Grant. SimplePolicyEngine relies on agent/server authorization.
CommonPolicyEngine is the standard implementation for an owner-approved initial preflight prefix.
CustomPolicy compiles a complete authored policy into its contract. Shared checkers have no custody.

## Public names

Every public type that authored policy, SDK integrations or contract specs name carries the
`Allowit` prefix: `AllowitContext`, `AllowitGrant`, `AllowitRule`, `AllowitError`,
`AllowitExecutionRequest`, `AllowitPolicyDeployment`, `AllowitState` and the others. Namespaced
items keep their short names, such as `allowit::Result` and `allowit::spent_cap`. A Soroban type
name appears only in the contract spec. Encodings carry struct field names and enum variant
symbols, so the prefix changes no signed bytes, digests or stored state.

## One portable policy source

Policy source is ordinary synchronous Rust against `crates/allowit`. The offchain server and
CustomPolicy compile the file verbatim:

```rust
use allowit::prelude::*;
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    allowit::transaction_cap(ctx, &ctx.grant.transaction_cap)?;
    allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
    allowit::recipients(ctx, &ctx.grant.recipients)?;
    Ok(())
}
```

The standard contract runs only its leading canonical calls, supplied by the owner as `rules`, and
skips unset fields. `scripts/contract_admin.py` derives `rules` from the source file. `scripts/policy_source.py` lexes
Rust comments, including nested block comments, and literals first, so they cannot add or hide calls.

Policy source names `allowit` only as the path root `allowit::`. Any other occurrence of the
identifier, such as `mod allowit`, `use core as allowit`, `extern crate`, `macro_rules! allowit` or
`fn allowit`, could rebind the crate that prefix calls name, so the tooling rejects it.

CustomPolicy compiles the file as a module with `#[path]`, and `SOURCE_HASH` covers only that file.
The file must therefore be the whole policy: it must not use `include!`, `include_str!`,
`include_bytes!`, `env!`, `option_env!`, `#[path]`, `cfg_attr` or an out-of-line `mod name;`. The
host portability test includes the file, so it must not use inner attributes or inner doc comments.
`check-policy-bindings.py` and the owner packet tooling of every tier reject all of these.

`allowit` has two backends that share one rule implementation. Feature `soroban` (default) uses
Soroban `Address`, `Vec` and contract types. Feature `std` uses heap strings and vectors
for the host evaluator; addresses are StrKey text. The selected backend backs the crate root that
authored policy names. The offchain server depends on
`allowit = { default-features = false, features = ["std"] }`. Enabling both backends is a compile
error, so a server cannot silently unify `soroban` through another crate. Feature `dual` enables
both for tests only. The CustomPolicy tests compile its source under both backends and require
identical pass values and errors on a shared vector set.

Portable authored code beyond canonical calls uses typed scalar fields and enum comparisons, such
as `ctx.request.operation == AllowitOperation::sep56_deposit`. Backend list methods differ (`len` returns
`u32` onchain and `usize` on the host), so authored code reads lists only through `recipients` and
`tokens`.

`AllowitContext` is the complete rule input. The wallet or server computes it:

| Field | Content |
| --- | --- |
| `grant` | Typed owner `AllowitGrant`. Each field is an `Option`; `None` is unset |
| `state` | Protected `AllowitAccountingHistory` proposed after this operation |
| `request` | Typed `AllowitOperation`, immutable asset, recipient (deposit vault), amount, `now`, `expires_at` |

Rules are pure checks: `allowit::<rule>(ctx, &Option<V>) -> allowit::Result<T>`. Each returns only
its passing constraint, or an `allowit::AllowitError`. An unset field is `MissingGrant`. Policy code calls
rules unguarded, so an unset parameter denies. Future server-only functions use the same shape.

| Rule and same-named Grant field | Native value | Pass value |
| --- | --- | --- |
| `transaction_cap` | Nonnegative `i128` gross units for one operation | `cap - amount` |
| `spent_cap` | Nonnegative `i128` cumulative irreversible-expense ceiling | `cap - state.spent` |
| `day_spent_cap` | Nonnegative `i128` UTC-day irreversible-expense ceiling | `cap - state.day_spent` |
| `day_total_cap` | Nonnegative `i128` UTC-day gross amount plus separate gas | `cap - state.day_total` |
| `call_cap` | `u64` successful operation count ceiling; zero denies | `cap - state.calls` |
| `recipients` | `Vec<Address>` permitted destinations, including vaults; empty denies | Matched recipient |
| `tokens` | `Vec<Address>` exact permitted SAC identities; empty denies | Matched asset |
| `expiry` | `u64` exclusive Unix timestamp; request expiry cannot exceed it | `expiry - now` |

Each rule checks only the facts it reads. A negative cap is `InvalidParameter`, as is a nonpositive
`transaction_cap` amount. A negative value that a cap reads is `InvalidState`; daily caps also
require `state.day == now / 86400`. Lifetime unpriced history denies `spent_cap`. Unpriced history
of the day denies both daily caps (`Unpriced`). The kernel enforces amount and history invariants
before rules run. Deployment rejects negative caps.

## Standard prefix

The standard prefix is the consecutive leading top-level statements of exactly the form
`allowit::<rule>(ctx, &ctx.grant.<rule>)?;`: one canonical rule and its same-named Grant field.
Any other statement ends it. Later statements run offchain or in CustomPolicy.
The standard contract receives the exact owner-approved ordered prefix as `rules: Vec<AllowitRule>`, never
caller selectors. `AllowitRule` is a typed enum whose variants are the canonical names. Soroban decodes
vector elements when read, so owner configuration decodes every rule and allowlist element before
storing it: an unknown name aborts and a malformed element is `InvalidGrant`. It runs each call through `allowit::preflight` as `if grant.<rule>.is_some() { allowit::<rule>(ctx, &grant.<rule>)?; }`
and discards pass values. This preflight runner is the only place an unset field skips its rule.
The offchain full policy still runs the unguarded call. Repeated rules read the same proposed
history, so they cannot charge twice.

Rule denials map to `PolicyDenied`. `MissingGrant` and `InvalidParameter` map to `InvalidGrant`.
`InvalidState` maps to `InvalidState`. A failed call rolls back its events, so only the host
evaluator and the shared engine return the specific rule error.

Protected `AllowitState.history` records every delegated success independently of selected or unset rules.
With cost bounds it records conservative expenses and gas. Without them it records raw gross and
calls plus an unpriced liability. Rollover clears only daily liability. No owner reconciliation or
refund method silently clears this history. No mutable business usage map exists. The kernel's
single-use `operation_id`, execution nonce and day checks reject replays, changed facts and
backward clocks before rules run.

## Source and configuration binding

Fixed standard `source_digest` is SHA-256 of canonical XDR containing the domain
`allowit_std_prefix`, implementation kind, actual module hash, immutable SAC, transfer/deposit schema
hashes and the ordered `Vec<AllowitRule>`. Each unit variant encodes as a one-symbol vector of its rule
name; its Grant reference is always the same-named field. It excludes Grant values and full source.
The constructor and binding getter check it against the actual runtime module.

Custom `source_digest` is the plain SHA-256 of the exact bytes of `crates/custom-policy/policy/policy.rs`.
`build.rs` computes `SOURCE_HASH` from the file that the contract compiles verbatim, so they
cannot drift. `ARGUMENT_SCHEMA_HASH` admits only `stellar::sep41_transfer`. The contract does not
depend on SDK-generated code. `scripts/check-policy-bindings.py` checks the schema binding.

The complete source has separate offline owner authorization, scoped to wallet, network, policy,
prefix and monotonic source revision. Changing only that offchain suffix needs no chain call.
Each execution separately carries `source_hash`, covered by agent/server authorization and the x402
digest. Offline updates do not replace already signed operation bytes or their recovery identity.

`deploy_policy` changes owner configuration at exactly the next `deployment_version`.
With `wasm_hash=None`, Grant values change without code redeployment. Prefix, history, custody,
execution nonce and pause remain intact when only Grant changes. The new revision rejects old
inflight packets. A changed prefix or executable requires a new owner binding.

Owner packets bind their exact meaning. Struct decoding ignores extra keys and reads absent
`Option` keys as `None`, so the constructor and `deploy_policy` require owner authorization for
the canonical re-encoding of the decoded packet. Bindings name the authored entrypoint `execute`. A packet with legacy, extra or absent keys fails
authorization unless the owner signed that canonical form.

`contract_version` 2 stores the typed Grant and `Vec<AllowitRule>`. Version 1 stored an untyped Grant map
and symbol rules. Execution, `state()` and `set_pause` accept only the exact canonical encoding of
version 2, including nested Grant and history. Owner `recover`, `invoke` and `deploy_policy` decode
a typed struct of only the fields they keep, so an in-place upgrade from version 1 never locks
custody. `deploy_policy` carries history over only in its exact canonical encoding. A complete
typed `deploy_policy` packet replaces Grant, rules and roles, keeps history, nonce, pause and
asset, and writes version 2. Later versions reject even owner calls, because their kept fields may
change meaning. New source and schema hashes need new owner bindings.

The reverse direction has no repair. Version 1 code reads State only in its own layout, so a
`deploy_policy` code change from version 2 to a version 1 release permanently locks custody. Each
wallet Wasm declares `allowit_custody_layout` metadata equal to `CONTRACT_VERSION`.
`contract_admin.py` refuses a code change to Wasm that declares another layout or none. Recover
funds before any change across layouts. Every later layout bump needs the same rule.

## Shared engine

The shared engine exposes each canonical rule as `<rule>(ctx: AllowitContext) -> Result<T, AllowitError>`.
Callers use its generated `EngineClient`.
It runs `allowit::<rule>(&ctx, &ctx.grant.<rule>)` and returns the same pass value or rule error.
It holds no custody, Grant or history. No policy wallet, release tool or server in this repository
calls it; offchain evaluation uses `allowit` directly. It remains the engine parent's administered
checker for onchain callers that cannot bundle `allowit`. Its tests match `AllowitRule` exhaustively, so a
new rule fails to compile until the engine exposes it. The `test-deny` fixture aborts every rule
with contract error `TEST_DENY` (1000), outside `allowit::AllowitError`. `engine_version` 2 marks this ABI.

## Expenses and native effects

An external payment spends principal plus attributable gas. A deposit retains principal as shares.
Its conversion cost plus attributable gas counts toward spent limits. Daily total includes principal
plus separate gas; embedded conversion fees are not counted twice. Underlying units use seven
decimals. Share units retain their independent native scale.

`AllowitExecutionRequest.expense` is optional bounded canonical XDR of `AllowitExpenseBounds`: asset, decimals,
gas units, conversion units, spent units, attributable fee ceiling, observation ledger and UTC day.
Unknown fields, wrong types, noncanonical maps, extra data and oversized bytes reject.
The server approves exact conservative economic ceilings. The kernel checks denomination, day,
ledger, operation class, nonnegative units and the fee/gas identity. It cannot observe final
transaction gas. XLM/stroop identity conversion is intrinsic; other gas conversions need an
admitted trusted source. Onchain counters retain ceilings. The server separately settles actual
expenses and temporary loss. No automatic onchain refund authority follows from that accounting.

`execute` and the owner-enabled x402 transfer hook require agent and server authority. The kernel
checks source/module/schema, immutable asset, exact parties/amount, positive debit, pause, expiry,
configuration version, execution nonce and single-use operation ID independently of business checks.
The x402 hook decodes its execution like `execute` and admits only the canonical transfer profile.
State, effects and receipts commit atomically. Denials and native failures roll them back.

SEP-56 deposits bind vault, assets, minimum shares and wallet source/operator/share receiver.
Ordinary `recipients` controls destination vaults; no separate vault list or code-hash pin applies.
The vault must report the immutable underlying SAC. Custody authorizes one exact deeper
`transfer(wallet, vault, assets)`. Extra debits, including a second debit later refunded, lack authority.
Returned shares must match the observed balance credit and meet the minimum. Any conversion-loss
ceiling also checks `preview_redeem(actual_shares)`. Foreign reads precede final balances.
The immutable SAC balance read is last. A vault getter cannot mutate already-checked effects.

`AllowitTransferReceipt` retains the underlying leg. `deposit_receipt(operation_id)` and `sep56_deposit`
record the observed share output. Vault code can misreport ownership, valuation or redeemability.
The wrapper bounds SAC spending and interface observations; it cannot prove investment value.
Owner `invoke` can redeem shares independently. The server reconciles actual settled redemptions.

## Owner authority and public metadata

Owner pause, configuration, recovery, upgrades and exact `invoke` bypass agent/server business checks
and never call an engine. Owner authorization binds exact target, arguments and supplied subtrees.
`policy_binding()` reports the default profile; `policy_binding_for(schema_digest)` checks another
admitted profile. `state()` returns the typed Grant and protected history.
Unknown stored layouts reject. Upgrades do not migrate state implicitly; only an explicit owner
packet rewrites a version 1 layout.

Classic G-address multisig has no contract prefix enforcement. Owner-selected signer thresholds
control native transactions. Its policy source and economic checks run offchain before signing.
