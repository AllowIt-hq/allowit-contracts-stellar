# Policy wallet engines

Wallets keep one immutable underlying Stellar Asset Contract (SAC). The owner selects code, agent,
independent server signer and Grant. `AllowitSimplePolicyEngine` relies on agent/server
authorization. `AllowitCommonPolicyEngine` is the standard implementation for an owner-approved
initial preflight prefix. `AllowitCustomPolicy` compiles a complete authored policy into its
contract. Shared checkers have no custody.

## Public names

Every public type that authored policy, SDK integrations or contract specs name carries the
`Allowit` prefix: `AllowitContext`, `AllowitEnv`, `AllowitGrant`, `AllowitRule`, `AllowitError`,
`AllowitExecutionRequest`, `AllowitPolicyDeployment`, `AllowitState` and the others. The contract
structs and their generated clients carry it too: `AllowitSimplePolicyEngine`,
`AllowitCommonPolicyEngine`, `AllowitCustomPolicy`, `AllowitEngine`, `AllowitEngineParent`, and
`AllowitEngineClient` and the other `*Client` types. Namespaced items keep their short names, such
as `allowit::Result` and `allowit::spent_cap`.

Encodings carry struct field names and enum variant symbols, not type names. The prefix therefore
leaves signed encodings, the standard prefix digest test vector and the stored layout unchanged.
Type names are in the Wasm contract spec, so rebuilt Wasm has new module hashes and, because the
standard `source_digest` hashes the module, new prefix-binding digests.

## One portable policy source

Policy source is ordinary synchronous Rust against `crates/allowit`. The offchain server and
`AllowitCustomPolicy` compile the file verbatim:

```rust
use allowit::prelude::*;
/// Let my agent pay our invoices. Cap every payment, cap its total spending and pay only vendors
/// I approve.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Cap every payment"
    allowit::transaction_cap(ctx, &ctx.grant.transaction_cap)?;
    // "cap its total spending"
    allowit::spent_cap(ctx, &ctx.grant.spent_cap)?;
    // "pay only vendors I approve"
    allowit::recipients(ctx, &ctx.grant.recipients)?;
    Ok(())
}
```

The function doc comment keeps the owner's original policy prompt. Each inline comment quotes the
prompt clause that the next call implements.

`AllowitCustomPolicy` and the offchain server run the function through `allowit::run`. A failed
rule ends the run with a denial: every rule records its error, and `run` returns the first rule
error recorded during the policy call even if the policy caught the error and returned `Ok`. The standard
contract runs only its leading canonical calls, supplied by the owner as `rules`, and
skips unset fields. `scripts/contract_admin.py` derives `rules` from the source file. `scripts/policy_source.py` lexes
Rust comments, including nested block comments, and literals first, so they cannot add or hide calls.

Policy source names `allowit` only as the path root `allowit::`. Any other occurrence of the
identifier, such as `mod allowit`, `use core as allowit`, `extern crate`, `macro_rules! allowit` or
`fn allowit`, could rebind the crate that prefix calls name, so the tooling rejects it.

`AllowitCustomPolicy` compiles the file as a module with `#[path]`, and `SOURCE_HASH` covers only that file.
The file must therefore be the whole policy: it must not use `include!`, `include_str!`,
`include_bytes!`, `env!`, `option_env!`, `#[path]`, `cfg_attr` or an out-of-line `mod name;`. The
names of those macros may appear only as the bare context field read `ctx.env`: after a single `.`
and not followed by `.`, `(` or `!`. So `ctx.env.storage()` and a value's Soroban `env()` method
reject. The host portability test includes the file, so it must not use inner attributes or inner
doc comments.

The same file must also behave the same offchain and onchain. The tooling therefore rejects:

- Code selected by build target or build profile: `cfg`, `cfg!`, `debug_assert!`,
  `debug_assert_eq!` and `debug_assert_ne!`. Debug assertions run in the plain-rustc smoke and in
  native tests but not in the release Wasm.
- `static` items. A mutable static, such as an atomic counter, keeps its value across evaluations
  in one server process, but starts again in every contract instance.
- Location, type, layout and width introspection: `module_path!`, `file!`, `type_name`,
  `type_name_of_val`, `Location`, `caller`, `TypeId`, `type_id`, `size_of`, `size_of_val`,
  `align_of`, `align_of_val`, `needs_drop`, `Layout`, `offset_of` and `BITS`. Host and Wasm types
  have different sizes and drop glue, so these reveal the backend.
- The pointer-width types `usize` and `isize`, which are 32 bits onchain and 64 bits on the host.
- Pointer introspection: raw pointer types (`*const`, `*mut`), `ptr`, `addr_of`, `addr_of_mut`,
  `as_ptr`, `as_mut_ptr`, `.addr()` and `expose_provenance`.
- Formatting: `fmt`, `write!`, `writeln!` and `format_args!`. Backend `Debug` output differs, and
  `{:p}` prints addresses.
- `unsafe`, `extern` items, `no_mangle`, `export_name`, `link_section` and `macro_rules!`.

The file must also not reach the dependencies of the including crate. In `AllowitCustomPolicy`
those include `soroban_sdk`, whose `Env::default()` gives a live host environment, and the wallet
crates. Every path and `use` tree must start at `allowit`, `core`, a fixed-width primitive type
such as `u32`, or a capitalized type, trait, enum or generic parameter such as `AllowitOperation`
or `Self`. Roots such as `soroban_sdk`, `std`, `alloc`, `allowit_policy_wallet`, `crate`, `super`,
`self`, a bare `::` (also after a keyword, as in `use ::core` or `return ::core`) or a lowercase
local module reject. The capitalized rule assumes that no direct dependency of an including crate
has a capitalized crate name. Macro definitions reject because they can assemble a path from
separate tokens. `scripts/policy_source.py` implements these checks; `check-policy-bindings.py` and
the owner packet tooling of every tier apply them.

These checks are lexical, so they cannot see types. Every owner source therefore also passes two
compiles:

- The std-only compile builds the file as a module of a `no_std` crate whose only dependency is
  `allowit` with only the `std` feature, as the offchain server uses it, with overflow checks on.
  A path into `soroban_sdk`, a wallet crate or any other crate fails there. So does a call to a
  Soroban `Env` or `Address` method, also through an alias such as `let e = &ctx.env;`, an
  address comparison with `<`, `min`, `max`, `sort` or `binary_search`, and a `std` prelude item
  such as `vec!`. On the host, `Address` is a StrKey newtype that compares only for equality:
  Soroban orders addresses by `ScAddress`, so accounts sort before contracts, while text would
  sort by StrKey. `scripts/policy_source.py` runs this compile in `check-policy-bindings.py`, and
  so in `scripts/build-contracts.sh`, and in `scripts/contract_admin.py` for the owner packets of
  every tier. These tools need `rustc` (from `RUSTC` or `PATH`). The portability test below and the
  `policy` job of `.github/workflows/contracts.yml` also compile `scripts/policy-smoke.rs`, which
  includes the branch sources, the same way.
- The Soroban compile builds the file into `AllowitCustomPolicy`. A host-only name, such as
  `allowit::AllowitEnv` or `Address::as_str`, fails there. `scripts/build-contracts.sh` runs it for
  the branch source. Build the reviewed custom Wasm from the owner source before deployment.

One known boundary remains. Values whose type Rust infers as `usize` without naming it, such as a
slice index or the result of `count()`, are 32 bits onchain and 64 bits on the host. Arithmetic or
`wrapping_*`, `checked_*` and `overflowing_*` calls on them can therefore differ. Neither the
lexical gate nor the two compiles can see an inferred type. Authored code must not compute with
such values; it reads lists only through `recipients` and `tokens`.

Integer overflow must behave the same: it panics, so the operation denies. The contract release
profile sets `overflow-checks = true`. The offchain server must build with `overflow-checks = true`
in every profile that evaluates policy, because Cargo's default release profile wraps on overflow.
The std-only compile, the smoke and the portability test pass `-Coverflow-checks=on` explicitly.

`allowit` has two backends that share one rule implementation. Feature `soroban` (default) uses
Soroban `Address`, `Vec`, `Env` and contract types. Feature `std` uses heap strings and vectors
for the host evaluator; addresses are unordered StrKey newtypes and the environment is a host
`AllowitEnv`. The selected backend backs the crate root that authored policy names. The offchain
server depends on `allowit = { default-features = false, features = ["std"] }` and builds with
`overflow-checks = true`. Enabling both backends is a compile error, so a server cannot silently
unify `soroban` through another crate.

The portability test, `crates/policy-wallet/src/portability_tests.rs`, runs one shared vector set,
`scripts/policy-vectors.rs`, through four targets:

1. The host backend: the std-only compile of `scripts/policy-smoke.rs` prints its outcomes.
2. `AllowitCustomPolicy`: the Soroban backend of the same sources must give identical pass values
   and errors. The real custom Wasm must then return the mapped policy result.
3. `AllowitCommonPolicyEngine`: the real standard Wasm, bound to the sample policy's prefix, must
   return the mapped first prefix preflight error. It skips unset Grant fields.
4. `AllowitSimplePolicyEngine`: the real simple Wasm must accept every vector that the kernel
   accepts.

The test seeds each Wasm with the vector's Grant and the history before the operation, so the
kernel proposes exactly the history that the host evaluated, and checks the committed history after
each success. Vectors that the kernel cannot produce, such as another UTC day, a deposit into the
transfer-only custom contract or a negative cap, run only on the two backends. Kernel violations
(another asset, payment to the wallet, request expiry, stale nonce, replay and pause) reject with the
same kernel error in all three contracts.

Portable authored code beyond canonical calls uses typed scalar fields and enum comparisons, such
as `ctx.request.operation == AllowitOperation::sep56_deposit`. Backend list methods differ (`len` returns
`u32` onchain and `usize` on the host), so authored code reads lists only through `recipients` and
`tokens`.

`AllowitContext` is the complete rule input. It is plain data without methods. The wallet or server
computes it:

| Field | Content |
| --- | --- |
| `env` | Backend environment: the contract's Soroban `Env` onchain, a stateless `AllowitEnv` on the host |
| `grant` | Typed owner `AllowitGrant`. Each field is an `Option`; `None` is unset |
| `state` | Protected `AllowitAccountingHistory` proposed after this operation |
| `request` | Typed `AllowitOperation`, immutable asset, recipient (deposit vault), amount, `now`, `expires_at` |

Rules are checks: `allowit::<rule>(ctx, &Option<V>) -> allowit::Result<T>`. Each returns only
its passing constraint, or an `allowit::AllowitError`. An unset field is `MissingGrant`. Policy code calls
rules unguarded, so an unset parameter denies. Future server-only functions use the same shape.

A failed rule also records its first error for the running evaluation, and `allowit::run`
denies with the first error recorded during the policy call after the policy returns. Policy code
therefore cannot turn a rule failure into a pass with `match`, `if let` or `let _`. A nested `run`
keeps the outer record. A failure recorded before `run` starts, for example by an earlier `run` in
the same invocation, does not deny it.

The record does not live in `ctx.env` on either backend, so policy code that clones the context,
replaces `ctx.env` or creates another environment cannot drop it. On the host, the record is a
thread-local of the evaluating thread, and `AllowitEnv` carries no state; the server creates one
with `AllowitEnv::new()` for every evaluation. Onchain, the record is a private
static in the memory of the running contract instance. Soroban runs every contract invocation in
a new VM instance, so the record starts empty and ends with the invocation. Native tests keep it
in a thread-local. The record is not ledger state: a failed rule reads and writes no storage entry,
and the standard preflight, the custom runner and the shared engine add nothing to the transaction
footprint for it. If state changes between simulation and apply and a rule then fails, the call
returns its typed error (`PolicyDenied`, `InvalidGrant` or the engine's `AllowitError`), not a
footprint trap. Authored code can name the `ctx.env` field but cannot call its methods, because the
two environments have none in common.

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
Any other statement ends it. Later statements run offchain or in `AllowitCustomPolicy`.
The standard contract receives the exact owner-approved ordered prefix as `rules: Vec<AllowitRule>`, never
caller selectors. `AllowitRule` is a typed enum whose variants are the canonical names. Soroban decodes
vector elements when read, so owner configuration decodes every rule and allowlist element before
storing it: an unknown name aborts and a malformed element is `InvalidGrant`. It runs each call through `allowit::preflight` as `if grant.<rule>.is_some() { allowit::<rule>(ctx, &grant.<rule>)?; }`
and discards pass values. This preflight runner is the only place an unset field skips its rule.
The offchain full policy and `AllowitCustomPolicy` still run the unguarded call, so they deny it
with `MissingGrant`. An unset prefix field is valid configuration: the owner can set or unset Grant
values with `deploy_policy` without code redeployment. `scripts/contract_admin.py` warns about it
without rejecting the packet. The preflight runner propagates the first rule error, so it does not
read the failure record. Repeated rules read the same proposed
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

`AllowitContext` carries the contract `Env`, so it is not a contract value. The shared engine
exposes each canonical rule as
`<rule>(grant: AllowitGrant, state: AllowitAccountingHistory, request: AllowitRequest) -> Result<T, AllowitError>`.
Callers use its generated `AllowitEngineClient`.
It builds the context with its own `Env`, runs `allowit::<rule>(&ctx, &ctx.grant.<rule>)` and
returns the same pass value or rule error.
It holds no custody, Grant or history. No policy wallet, release tool or server in this repository
calls it; offchain evaluation uses `allowit` directly. It remains the engine parent's administered
checker for onchain callers that cannot bundle `allowit`. Its tests match `AllowitRule` exhaustively, so a
new rule fails to compile until the engine exposes it. The `test-deny` fixture aborts every rule
with contract error `TEST_DENY` (1000), outside `allowit::AllowitError`. `engine_version` 3 marks this ABI.
It replaces the shipped release 1 ABI, whose methods take `(request: EngineRequest, state:
EngineState)`. Release 2 was never released. An `upgrade_engine` from a deployed release 1 engine
to release 3 breaks every onchain caller of the release 1 methods, so migrate or retire those
callers first.

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
