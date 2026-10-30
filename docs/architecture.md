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

`AllowitCustomPolicy` and the offchain server call `execute` directly. Only an error that the
policy returns, usually with `?`, denies. A policy may catch a rule error, read it, record it in
its own state and continue. The standard contract runs only its leading canonical calls, supplied
by the owner as `rules`, and skips unset fields. `scripts/contract_admin.py` derives `rules` from the source file. `scripts/policy_source.py` lexes
Rust comments, including nested block comments, and literals first, so they cannot add or hide calls.

Policy source names `allowit` only as the path root `allowit::`. Any other occurrence of the
identifier, such as `mod allowit`, `use core as allowit`, `extern crate`, `macro_rules! allowit` or
`fn allowit`, could rebind the crate that prefix calls name, so the tooling rejects it.

`AllowitCustomPolicy` compiles the file as a module with `#[path]`, and `SOURCE_HASH` covers only that file.
The file must therefore be the whole policy: it must not use `include!`, `include_str!`,
`include_bytes!`, `env!`, `option_env!`, `#[path]`, `cfg_attr` or an out-of-line `mod name;`. The
names of those macros may appear only as the bare context field read `ctx.env`: after a single `.`
and not followed by `.`, `(` or `!`. So `ctx.env.storage()` and a value's Soroban `env()` method
reject. The field is read-only: an assignment such as `c.env = ...` and a `&mut c.env` borrow,
which `core::mem::replace` could use, reject, and so does the name `AllowitEnv`. The host
portability test includes the file, so it must not use inner attributes or inner doc comments.

The same file must also behave the same offchain and onchain, where `usize` is 32 and 64 bits
wide, backend lists differ and code addresses differ. `scripts/policy_source.py` therefore admits
code through an allowlist, not a list of known hazards. Every identifier must be one of:

- an allowed keyword: `fn`, `const`, `let`, `mut`, `ref`, `pub`, `use`, `if`, `else`, `match`,
  `for`, `in`, `while`, `loop`, `break`, `continue`, `return`, `true` and `false`;
- a listed field after `.`: `env`, `grant`, `request`, the Grant fields and the request fields;
- a listed method after `.`: comparisons, `clone`, and the `Option`, `Result`, fixed-width integer,
  `bool` and `Ordering` methods that take and return no pointer-width value, such as `is_some`,
  `unwrap_or`, `checked_add`, `saturating_sub`, `min` and `max`;
- a listed path: the `allowit` rules, `get_state`, `set_state`, the server-only functions and
  types, the `AllowitOperation`, `AllowitError` and `AllowitRule` variants, `Option` and `Result`
  variants, `MAX`, `MIN`, `from` and `try_from` of the fixed-width integers, and
  `core::cmp::{min, max, Ordering}`;
- a listed type (`AllowitContext`, `AllowitError`, `AllowitGrant`, `AllowitOperation`,
  `AllowitRequest`, `AllowitRule`, `Address`, `Result`, `Option`, `DAY` and the variants
  `Some`, `None`, `Ok`, `Err`), a constant the file defines or an `allowit` type it imports;
- a lowercase name the file declares: a function or constant name, a function parameter, or a
  `let`, `for` or match-arm binding;
- a fixed-width primitive type: the `i` and `u` integers of 8 to 128 bits, `bool`, `char` and `str`.

`use` admits only `use allowit::prelude::*;` and imports of `allowit` types. The allowlist
therefore rejects, among others: `usize`, `isize` and float types and literals; casts (`as`);
closures and function values, including function pointer types and the `Some`, `Ok` and `Err`
constructors when not called, because they compare by code address; the prelude functions
`size_of`, `size_of_val`, `align_of`, `align_of_val` and `drop`, because type sizes differ
between the backends (a host `Address` is a 24-byte string, onchain an 8-byte handle); raw pointers; qualified (`<T>::`) and generic type paths; modules, traits, impls, structs,
enums, statics, `unsafe`, `extern` and paths into the including crate (`crate`, `super`, `self`);
`ctx.state`, which policy reads only through `allowit::get_state`; and every `core` API outside the
list, such as `NonZeroUsize`, `ilog2`, `count_ones`, `len` or `Utf8Error::valid_up_to`. A local
function name may only be called. Non-ASCII identifiers reject.

Beside the allowlist, the tooling rejects:

- Every macro other than `assert!`, `assert_eq!`, `assert_ne!`, `panic!`, `matches!` and
  `unreachable!`. `core::arch::global_asm!` is safe code without `unsafe` that emits native code.
  Linked into the offchain evaluator, it could run before `main`, while the Soroban compile rejects it.
- Every attribute other than `allow`, `expect`, `warn`, `deny`, `forbid`, `inline`, `cold` and
  `must_use`, for example `track_caller`, `doc` or `cfg`.
- List access other than through the list rules. `recipients` and `tokens` may appear only in the
  call `allowit::<list>(<ctx>, &<ctx>.grant.<list>)`, with the same list name twice, and as
  `AllowitRule` variants. A struct expression or pattern of `AllowitGrant` or `AllowitContext` and
  struct update syntax `..` reject. Soroban and heap vectors have different methods with the same
  names: for example `append` drains its argument only on the host.
- Indexing (`x[i]`), whose index Rust infers as `usize`.

`scripts/policy_source.py` implements these checks; `check-policy-bindings.py` and the owner packet
tooling of every tier apply them.

These checks are lexical, so they cannot see types. Every owner source therefore also passes two
compiles:

- The std-only compile builds the file as a module of a `no_std` crate whose only dependency is
  `allowit` with only the `std` feature, as the offchain server uses it, with overflow checks on
  and `-D unpredictable_function_pointer_comparisons`: a function pointer `==` that the lexical
  checks miss fails there, because its result changes with the optimization level. A path into `soroban_sdk`, a wallet crate or any other crate fails there. So does a call to a
  Soroban `Env` or `Address` method, also through an alias such as `let e = &ctx.env;`, an
  address comparison with `<`, `min`, `max`, `sort` or `binary_search`, and a `std` prelude item
  such as `vec!`. On the host, `Address` is a StrKey newtype that compares only for equality:
  Soroban orders addresses by `ScAddress`, so accounts sort before contracts, while text would
  sort by StrKey. `scripts/policy_source.py` runs this compile in `check-policy-bindings.py`, and
  so in `scripts/build-contracts.sh`, and in `scripts/contract_admin.py` for the owner packets of
  every tier. These tools need `rustc` (from `RUSTC` or `PATH`). The portability test below and the
  `policy` job of `.github/workflows/contracts.yml` also compile `scripts/policy-smoke.rs`, which
  includes the branch sources, the same way.
- The Soroban compile builds the file into `AllowitCustomPolicy`. A host-only item, such as
  `Address::new`, fails there. `scripts/build-contracts.sh` runs it for
  the branch source. Build the reviewed custom Wasm from the owner source before deployment.

The allowlist is lexical: a name passes by spelling. A listed method name therefore also passes on
an unlisted receiver type. The listed names take and return no pointer-width value on every type
that portable code can produce, because no listed path, type or method yields a `usize`, slice,
iterator or pointer. Extend the allowlist only with names that keep that property.

Integer overflow must behave the same: it panics, so the operation denies. The contract release
profile sets `overflow-checks = true`. The offchain server must build with `overflow-checks = true`
in every profile that evaluates policy, because Cargo's default release profile wraps on overflow.
The std-only compile, the smoke and the portability test pass `-Coverflow-checks=on` explicitly.

Execution must be bounded the same way. Onchain, the Soroban budget stops a policy that loops or
recurses without end, and the operation denies. A host process has no such budget: `loop {}` never
returns, and deep recursion overflows the stack, which aborts the whole process because Rust
cannot catch a stack overflow. For Simple and Common wallets, the host run is the only evaluation
of the full policy. The offchain server must therefore evaluate each policy in an isolated worker
process with CPU-time, wall-clock, stack and memory limits. A timeout, crash, abort or panic of the
worker counts as a denial. The worker must build with `panic = "unwind"` if it catches panics in
process; otherwise the process boundary turns every panic into a denial. One owner's policy must
not be able to stop or slow evaluations for other wallets.

`allowit` has two backends that share one rule implementation. Feature `soroban` (default) uses
Soroban `Address`, `Vec`, `Map`, `Env` and contract types. Feature `std` uses heap strings, maps
and vectors for the host evaluator; addresses are unordered StrKey newtypes and the environment is
a host `AllowitEnv`, which buffers the policy's state writes. The selected backend backs the crate root that authored policy names. The offchain
server depends on `allowit = { default-features = false, features = ["std"] }` and builds with
`overflow-checks = true`. Enabling both backends is a compile error, so a server cannot silently
unify `soroban` through another crate.

The portability test, `crates/policy-wallet/src/portability_tests.rs`, runs one shared vector set,
`scripts/policy-vectors.rs`, through four targets:

1. The host backend: the std-only compile of `scripts/policy-smoke.rs` prints its outcomes.
2. `AllowitCustomPolicy`: the Soroban backend of the same sources must give identical pass values,
   errors and post-flight state. The real custom Wasm must then return the mapped policy result.
   A fixture Wasm built with the `test-catching` feature compiles `src/catching_policy.rs`
   instead, and must return the mapped catching result. That policy catches a daily cap error,
   counts it in its own state key and continues, at most twice.
3. `AllowitCommonPolicyEngine`: the real standard Wasm, bound to the sample policy's prefix, must
   return the mapped first prefix preflight error. It skips unset Grant fields.
4. `AllowitSimplePolicyEngine`: the real simple Wasm runs no rules.

Every contract then returns the shared post-flight result. Each vector holds the current state
before the operation. The test seeds each Wasm with the vector's Grant and that state, and checks
that each success stores exactly the post-flight state that the host computed. Vectors that the
kernel cannot produce, such as a deposit into the transfer-only custom contract or a negative cap,
run only on the two backends. Kernel violations
(another asset, payment to the wallet, request expiry, stale nonce, replay and pause) reject with the
same kernel error in every contract.

`scripts/build-contracts.sh` builds the test-feature fixtures (`engine_deny.wasm` and
`custom_catching.wasm`) in their own target directory and copies them to `target/test-fixtures`,
so the deployable release paths never hold a test artifact. The tests read every Wasm from the
default `target/` directory, so the script ignores `CARGO_TARGET_DIR`. Run one build or
`cargo test` at a time in a worktree; a lock directory stops a second concurrent build. Use another
worktree for concurrent runs. The mainnet tooling rejects any artifact whose hash matches a test
fixture.

Portable authored code beyond canonical calls uses typed scalar fields, enum comparisons such as
`ctx.request.operation == AllowitOperation::sep56_deposit`, and its own state keys. Backend list
methods differ (`len` returns `u32` onchain and `usize` on the host), so the tooling allows lists
only as arguments of `recipients` and `tokens`.

`AllowitContext` is the complete rule input. It is plain data without methods. The wallet or server
computes it:

| Field | Content |
| --- | --- |
| `env` | Backend environment: the contract's Soroban `Env` onchain, an `AllowitEnv` on the host |
| `grant` | Typed owner `AllowitGrant`. Each field is an `Option`; `None` is unset |
| `state` | Current policy state before this operation: one free-form map of standard and policy-defined keys |
| `request` | Typed `AllowitOperation`, immutable asset, recipient (deposit vault), amount, `now`, `expires_at`, and `spent_units` and `gas_units` from the validated expense bounds, or `unpriced` |

Rules are checks: `allowit::<rule>(ctx, &Option<V>) -> allowit::Result<T>`. Each returns only
its passing constraint, or an `allowit::AllowitError`. An unset field is `MissingGrant`. Policy code
calls rules unguarded, so an unset parameter denies. A rule error that the policy catches denies
nothing: the policy decides.

The state map holds the standard keys `spent`, `day_spent`, `day_total`, `calls`, `day`,
`unpriced` and `day_unpriced`, and any keys the policy defines. `AllowitStandardState` decodes the
standard keys in one place; an absent key is zero or false, and a value of another type is
`InvalidState`. Policy code reads a key with `allowit::get_state(ctx, key)`, which sees the state
before this operation, and records a write with `allowit::set_state(ctx, key, value)`. Values are
`i128`, `u64` or `bool`; a key is 1 to 32 ASCII letters, digits or underscores. Writes are held in
the environment: in contract temporary storage onchain and in `AllowitEnv` on the host. `ctx`
stays plain data.

`allowit::post_flight(ctx)` computes the state after an approved operation. The wallet and the
server run the same function. It rolls the UTC day over, adds one call, adds `spent_units` to
`spent` and `day_spent`, adds the amount and `gas_units` to `day_total`, and marks `unpriced` and
`day_unpriced` for a request without expense bounds. It then applies the policy's writes, which may
replace a standard key: owner-signed code is trusted, and no key is reserved. A merged state whose
standard keys later operations could not decode, such as `calls` written as a `bool`, a negative
`spent` or a later `day`, is `InvalidState`: the operation denies instead of locking the wallet.
`post_flight` consumes the write buffer first, even when it fails.

The server evaluates a policy with `allowit::evaluate(ctx, execute)`. It clears stale writes, runs
`execute`, and runs `post_flight` on approval; a denial discards the policy's writes. So no write
outlives its evaluation, also when the server reuses an `AllowitEnv`. Onchain, the wallet runs
`post_flight` after its own policy check, and a denied transaction rolls the temporary buffer back.

The server-only enrichment functions `price`, `fetch`, `internet_search`, `marketplace_search`,
`systemone`, `request_screening` and `clear_systemone_context` exist only in the host backend.
There they are stubs that return `Unsupported` until the server fills them. A Custom policy that
calls one does not compile, because the Soroban backend has none of them.

| Rule and same-named Grant field | Native value | Pass value |
| --- | --- | --- |
| `transaction_cap` | Nonnegative `i128` gross units for one operation | `cap - amount` |
| `spent_cap` | Nonnegative `i128` cumulative irreversible-expense ceiling | `cap - (spent + spent_units)` |
| `day_spent_cap` | Nonnegative `i128` UTC-day irreversible-expense ceiling | `cap - (today_spent + spent_units)` |
| `day_total_cap` | Nonnegative `i128` UTC-day gross amount plus separate gas | `cap - (today_total + amount + gas_units)` |
| `call_cap` | `u64` successful operation count ceiling; zero denies | `cap - (calls + 1)` |
| `recipients` | `Vec<Address>` permitted destinations, including vaults; empty denies | Matched recipient |
| `tokens` | `Vec<Address>` exact permitted SAC identities; empty denies | Matched asset |
| `expiry` | `u64` exclusive Unix timestamp; request expiry cannot exceed it | `expiry - now` |

`today_spent` and `today_total` are the daily values when `state.day == now / 86400`, and zero for
an earlier day. A later day is `InvalidState`. Each rule checks only the facts it reads. A negative
cap is `InvalidParameter`, as are a nonpositive `transaction_cap` amount and negative request
units. A negative state value that a cap reads is `InvalidState`. Lifetime unpriced state or an
unpriced request denies `spent_cap`; unpriced state of the day or an unpriced request denies both
daily caps (`Unpriced`). A sum outside its integer range is `Overflow`. Deployment rejects negative
caps.

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
without rejecting the packet. The preflight runner propagates the first rule error. Repeated rules
read the same current state and only `post_flight` charges, so a rule cannot charge twice.

Rule denials map to `PolicyDenied`. `MissingGrant` and `InvalidParameter` map to `InvalidGrant`.
`InvalidState` maps to `InvalidState`, `Overflow` to `Overflow` and `Unsupported` to
`UnsupportedOperation`. A failed call rolls back its events, so only the host
evaluator and the shared engine return the specific rule error.

`AllowitState.policy_state` records every delegated success independently of selected or unset
rules. With cost bounds it records conservative expenses and gas. Without them it records raw gross
and calls plus an unpriced liability. Rollover clears only daily liability. No owner reconciliation
or refund method clears the standard keys. The kernel's single-use `operation_id`, execution nonce
and expense day checks reject replays and changed facts before rules run; a backward ledger day
fails the daily rules and `post_flight` with `InvalidState`.

After the policy approves, the wallet writes the post-flight state, the next nonce and the replay
marker before it calls the token or the vault. Soroban transactions are atomic, so a later failed
effect check rolls all of it back. Soroban also refuses a call into a contract that is already on
the call stack, so a hostile vault cannot call `execute` or reach the x402 hook while the wallet's
operation runs; the transaction fails and no state changes.

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
With `wasm_hash=None`, Grant values change without code redeployment. Prefix, policy state, custody,
execution nonce and pause remain intact when only Grant changes. The new revision rejects old
inflight packets. A changed prefix or executable requires a new owner binding.

Owner packets bind their exact meaning. Struct decoding ignores extra keys and reads absent
`Option` keys as `None`, so the constructor and `deploy_policy` require owner authorization for
the canonical re-encoding of the decoded packet. Bindings name the authored entrypoint `execute`. A packet with legacy, extra or absent keys fails
authorization unless the owner signed that canonical form.

`contract_version` 3 stores the typed Grant, `Vec<AllowitRule>` and the free-form
`policy_state` map. Version 2 stored a typed accounting history struct, and version 1 an untyped
Grant map and symbol rules. Execution, `state()`, `policy_state()` and `set_pause` accept only the
exact canonical encoding of version 3, including the nested Grant. Owner `recover` and `invoke`
decode a typed struct of only the fields they keep, so an in-place upgrade from an earlier layout
never locks recovery. `deploy_policy` carries `policy_state` over; an earlier layout has none, so
`deploy_policy` rejects it with `InvalidState`. No layout migrates implicitly: recover funds from an
earlier layout and deploy a new wallet. A complete typed `deploy_policy` packet replaces Grant,
rules and roles, keeps policy state, nonce, pause and asset, and writes version 3. Later versions
reject even owner calls, because their kept fields may change meaning. New source and schema
hashes need new owner bindings.

Earlier code reads State only in its own layout, so a `deploy_policy` code change from version 3
to an earlier release permanently locks custody. Each
wallet Wasm declares `allowit_custody_layout` metadata equal to `CONTRACT_VERSION`.
`contract_admin.py` refuses a code change to Wasm that declares another layout or none. Recover
funds before any change across layouts. Every later layout bump needs the same rule.

## Shared engine

`AllowitContext` carries the contract `Env`, so it is not a contract value. The shared engine
exposes each canonical rule as
`<rule>(grant: AllowitGrant, state: Map<Symbol, Val>, request: AllowitRequest) -> Result<T, AllowitError>`,
where `state` is the current policy state.
Callers use its generated `AllowitEngineClient`.
It builds the context with its own `Env`, runs `allowit::<rule>(&ctx, &ctx.grant.<rule>)` and
returns the same pass value or rule error.
It holds no custody, Grant or policy state. No policy wallet, release tool or server in this repository
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
admitted profile. `state()` returns the custody State, and `policy_state()` the current policy
state map. Unknown stored layouts reject. Upgrades do not migrate state.

Classic G-address multisig has no contract prefix enforcement. Owner-selected signer thresholds
control native transactions. Its policy source and economic checks run offchain before signing.

## Crate boundaries

`crates/allowit` holds the shared rule core (`core.rs`) and both backends. The core with the host
backend becomes `sdk/core` in the SDK repository, for the offchain server and SDK evaluator. The
Soroban backend with the policy wallet, protocol, custom policy and engine crates becomes
`stellar/core`. Authored policy names only `allowit::`, so the split does not change policy source.
