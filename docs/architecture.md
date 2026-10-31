# Policy wallet engines

Wallets keep one immutable underlying Stellar Asset Contract (SAC). The owner selects code, agent,
independent server signer and params. `AllowitSimplePolicyEngine` relies on agent/server
authorization. `AllowitCommonPolicyEngine` is the standard implementation for an owner-approved
initial preflight prefix. `AllowitCustomPolicy` compiles a complete authored policy into its
contract. Shared checkers have no custody.

## Public names

Every public type that authored policy, SDK integrations or contract specs name carries the
`Allowit` prefix: `AllowitContext`, `AllowitEnv`, `AllowitParams`, `AllowitValue`, `AllowitRule`,
`AllowitError`, `AllowitExecutionRequest`, `AllowitPolicyDeployment`, `AllowitState` and the others. The contract
structs and their generated clients carry it too: `AllowitSimplePolicyEngine`,
`AllowitCommonPolicyEngine`, `AllowitCustomPolicy`, `AllowitEngine`, `AllowitEngineParent`, and
`AllowitEngineClient` and the other `*Client` types. Namespaced items keep their short names, such
as `allowit::Result`, `allowit::spent_cap` and `allowit::TRANSACTION_CAP`.

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
    allowit::transaction_cap(ctx, ctx.params.get(allowit::TRANSACTION_CAP))?;
    // "cap its total spending"
    allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
    // "pay only vendors I approve"
    allowit::recipients(ctx, ctx.params.get(allowit::RECIPIENTS))?;
    Ok(())
}
```

`execute` takes only the context. Each rule call keeps the form
`allowit::<rule>(ctx, ctx.params.get(<key>))?`: the policy looks up the param and the rule decodes
the value. A rule may read any key, such as a custom `vendor_cap`.

The function doc comment keeps the owner's original policy prompt. Each inline comment quotes the
prompt clause that the next call implements.

`AllowitCustomPolicy` and the offchain server call `execute` directly. Only an error that the
policy returns, usually with `?`, denies. A policy may catch a rule error, read it, record it in
its own state and continue. The standard contract runs only its leading canonical calls, supplied
by the owner as `rules`, and skips absent params. `scripts/contract_admin.py` derives `rules` from the source file. `scripts/policy_source.py` lexes
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
- a listed field after `.`: `env`, `params`, `request` and the request fields, including `args`;
- a listed method after `.`: comparisons, `clone`, and the `Option`, `Result`, fixed-width integer,
  `bool` and `Ordering` methods that take and return no pointer-width value, such as `is_some`,
  `unwrap_or`, `checked_add`, `saturating_sub`, `min` and `max`, and `get` on `params` and `args`
  only;
- a listed path: the `allowit` rules, `param`, `get_state`, `set_state`, the canonical key
  constants, the server-only functions and their request types, the `AllowitOperation`,
  `AllowitError`, `AllowitRule` and `AllowitValue` variants, `Option` and `Result` variants,
  `MAX`, `MIN`, `from` and `try_from` of the fixed-width integers, and `core::cmp::{min, max,
  Ordering}`;
- a listed type (`AllowitContext`, `AllowitError`, `AllowitOperation`, `AllowitRequest`,
  `AllowitRule`, `AllowitValue`, `Address`, `Result`, `Option`, `DAY` and the variants `Some`,
  `None`, `Ok`, `Err`), a canonical key constant, a server request type, a constant the file
  defines or an `allowit` type it imports;
- a field name of a server request struct expression, such as `query:`;
- a lowercase name the file declares: a function or constant name, a function parameter, or a
  `let`, `for` or match-arm binding;
- a fixed-width primitive type: the `i` and `u` integers of 8 to 128 bits, `bool`, `char` and `str`.

`use` admits only `use allowit::prelude::*;` and imports of `allowit` types. The allowlist
therefore rejects, among others: `usize`, `isize` and float types and literals; casts (`as`);
closures and function values, including function pointer types and the `Some`, `Ok`, `Err` and
`AllowitValue` constructors when not called, because they compare by code address; the prelude functions
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
- A string literal whose value holds a brace other than the placeholders `{}` and `{:?}` and the
  escapes `{{` and `}}`. The allowed macros read their message as a format string, and a width or
  precision count, such as `{:1$}`, `{:.*}` or `{:a$}`, is a `usize`: it makes an unsuffixed
  binding a `usize` without naming the type. The check decodes escapes first, so `\x7b` and
  `\u{7b}` cannot spell a brace.
- Every attribute other than `allow`, `expect`, `warn`, `deny`, `forbid`, `inline`, `cold` and
  `must_use`, for example `track_caller`, `doc` or `cfg`.
- The map inside `params` and `args`, such as `ctx.params.0`, and the name `AllowitParams`. Soroban
  maps key by `Symbol` and decode values on read, and heap maps have other methods, so params and
  args are read only with `.get(key)`. The host backend keeps that map private, so the std-only
  compile also rejects `.0` on a clone or a binding, such as `ctx.params.clone().0`. `get` passes
  only on the field access `.params` or `.args`, such as `ctx.params.get` or
  `ctx.request.args.get`, and the file may not declare `params` or `args` as a binding or function
  name: on a list or a string, `get` would take a pointer-width index on the host. A struct expression or pattern of
  `AllowitContext`, which would reach `state`, and struct update syntax `..` reject. Soroban and
  heap vectors have different methods with the same names, for example `append` drains its argument
  only on the host, so a list from `AllowitValue::List` admits only comparison, `clone`, matching
  and `for`.
- Indexing (`x[i]`), whose index Rust infers as `usize`.

`scripts/policy_source.py` implements these checks; `check-policy-bindings.py` and the owner packet
tooling of every tier apply them.

These checks are lexical, so they cannot see types. Every owner source therefore also passes two
compiles:

- The std-only compile builds the file as a module of a `no_std` crate whose only dependency is
  `allowit` with only the `std` feature, as the offchain server uses it, with overflow checks on
  and `-F unpredictable_function_pointer_comparisons`: a function pointer `==` that the lexical
  checks miss fails there, because its result changes with the optimization level. The lint is
  forbidden, so a source `#[allow]`, `#[expect]` or `#[warn]` on it also fails. A path into `soroban_sdk`, a wallet crate or any other crate fails there. So does a call to a
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
an unlisted receiver type. No listed path, type or method takes or returns a `usize`, slice,
iterator or pointer on a type that portable code can produce. A name is not the only way to reach a
`usize`: Rust also infers one from a format width or precision count, which the placeholder check
above rejects, and from an index, which rejects too. Extend the allowlist, the macros and the
placeholders only with forms that keep this property.

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
   counts it in its own state key and continues, at most twice. When the agent's args name an
   `invoice`, it also caps the payment with the custom `invoice_cap` param.
3. `AllowitCommonPolicyEngine`: the real standard Wasm, bound to the sample policy's prefix, must
   return the mapped first prefix preflight error. It skips absent params and rejects a custom
   param with `InvalidParam`.
4. `AllowitSimplePolicyEngine`: the real simple Wasm runs no rules and also rejects a custom param.

Every contract then returns the shared post-flight result. Each vector holds the current state
before the operation. The test seeds each Wasm with the vector's params, args and that state, and
checks that each success stores exactly the post-flight state that the host computed. Both backends
also agree that the standard post-flight denies the catching policy's write with `Unsupported`,
that a write past `MAX_STATE_KEYS` keys or `MAX_STATE_BYTES` bytes is `InvalidState`, that
`evaluate` denies more than 16 args with `InvalidParam`, and that a standard `evaluate` rejects a
custom param with `InvalidParam`.
Separate tests check that every tier stores exactly the state that the server's `evaluate`
returned, and that execution params reach the Custom policy, fail authorization when changed after
signing, reject beyond their bounds and leave the standard tiers unaffected. Vectors that the
kernel cannot produce, such as a deposit into the transfer-only custom contract, a negative cap or
more than 16 args, run only on the two backends. Kernel violations
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
`ctx.request.operation == AllowitOperation::sep56_deposit`, matches on `AllowitValue`, and its own
state keys. Backend list methods differ (`len` returns `u32` onchain and `usize` on the host), so
the tooling admits no list method.

`AllowitContext` is the complete rule input. It is plain data without methods. The wallet or server
computes it:

| Field | Content |
| --- | --- |
| `env` | Backend environment: the contract's Soroban `Env` onchain, an `AllowitEnv` on the host |
| `params` | The owner's constructor params, key => `AllowitValue`. An absent key is unset |
| `state` | Current policy state before this operation: one free-form map of standard and policy-defined keys |
| `request` | Typed `AllowitOperation`, immutable asset, recipient (deposit vault), amount, `now`, `expires_at`, `spent_units` and `gas_units` from the validated expense bounds, or `unpriced`, and the agent's `args` |

Params, state and args share one value type, `AllowitValue`: `Int(i128)`, `Bool(bool)`,
`Str(String)`, `Addr(Address)` and `List(Vec<AllowitValue>)`. Onchain a map is
`Map<Symbol, AllowitValue>`, on the host `BTreeMap<String, AllowitValue>`. `params` and
`request.args` are `AllowitParams`, which wraps that map and offers authored policy only
`get(key) -> Option<AllowitValue>`. The host map is private; the server converts with `From`. Values are owned on both backends, because Soroban maps decode
them on read; a borrowed host value would bind differently in a `match`. A key that no map can
hold, such as one with a space, is unset on both backends.

Rules are checks: `allowit::<rule>(ctx, Option<AllowitValue>) -> allowit::Result<T>`. Each decodes
the value, then returns only its passing constraint, or an `allowit::AllowitError`. An unset param is
`MissingParam`; a value of the wrong type or range is `InvalidParam`. Policy code calls rules
unguarded, so an unset param denies. A rule error that the policy catches denies nothing: the
policy decides. Custom keys reach policy as `ctx.params.get("vendor_cap")` or as
`allowit::param(ctx, "vendor_cap")`, which returns the value or `MissingParam`.

The owner sets params at install and changes them with `deploy_policy`, without code redeployment.
The canonical keys are `allowit::TRANSACTION_CAP`, `SPENT_CAP`, `DAY_SPENT_CAP`, `DAY_TOTAL_CAP`,
`CALL_CAP`, `RECIPIENTS`, `TOKENS` and `EXPIRY`, each the name of its rule.
`allowit::check_params` checks every owner write. Simple and Common admit only the canonical keys,
each with the type its rule decodes: a nonnegative `Int` cap, an `Int` in the `u64` range for
`call_cap` and `expiry`, and a `List` of `Addr` for `recipients` and `tokens`. Custom admits up to
32 keys, whose meaning its policy defines. Every value holds at most 64 nested values, and every
text at most 256 bytes. Nothing checks that a rule reads its own key.

Params, args and state also have byte budgets: `MAX_PARAM_BYTES`, `MAX_ARG_BYTES` and
`MAX_STATE_BYTES`, 16 KiB each. Both backends count a map's encoded size the same way: 40 bytes per
key, 80 per value and each text padded to four bytes. This count is at least the XDR size. The
wallet stores params and policy state in its one instance entry, so the two budgets keep that
entry far below the network's contract data entry limit, 64 KiB in current settings. Every
standard params map fits its budget.

The agent supplies execution params per call in `AllowitExecutionRequest.args`, at most 16 keys
with the same key and value bounds. An empty key, which a Soroban `Symbol` can hold, is
`InvalidParam` in params and args on both backends. The agent and server authorize the whole request, so a changed arg
fails authorization. The wallet passes them to policy as `ctx.request.args` and never stores them.
Canonical rules and the standard contract ignore them; Custom and offchain policy read them with
`ctx.request.args.get("key")`.

The state map holds the standard keys `spent`, `day_spent`, `day_total`, `calls`, `day`,
`unpriced` and `day_unpriced`, and any keys the policy defines, at most `allowit::MAX_STATE_KEYS`
(39) keys and `MAX_STATE_BYTES` in all: the seven standard keys and 32 policy keys. `AllowitStandardState` decodes the
standard keys in one place; an absent key is zero or false, and a value of another type or range,
such as a negative `calls`, is `InvalidState`. Policy code reads a key with
`allowit::get_state::<V>(ctx, key)`, which sees the state before this operation and decodes the
`AllowitValue` as `V`: `i128`, `u64`, `bool`, `Address` or `AllowitValue`. It records a write with
`allowit::set_state(ctx, key, value)`, where the value converts into an `AllowitValue` within the
value bounds; a key is 1 to 32 ASCII letters, digits or underscores. Writes are held in the
environment: in contract temporary storage onchain and in `AllowitEnv` on the host. `ctx` stays
plain data.

`allowit::post_flight(ctx, tier)` computes the state after an approved operation. The wallet and
the server run the same function. It rolls the UTC day over, adds one call, adds `spent_units` to
`spent` and `day_spent`, adds the amount and `gas_units` to `day_total`, and marks `unpriced` and
`day_unpriced` for a request without expense bounds. It then applies the policy's writes, which may
replace a standard key: owner-signed code is trusted, and no key is reserved. A merged state whose
standard keys later operations could not decode, such as `calls` written as a `bool`, a negative
`spent` or a later `day`, is `InvalidState`. So is a merged state with `calls` at `u64::MAX`, or
with `spent`, `day_spent` or `day_total` at `i128::MAX`: the next standard update would overflow
before any repair write applies. So is a merged state with more than `MAX_STATE_KEYS` keys or
`MAX_STATE_BYTES` bytes: no call deletes a state key and `deploy_policy` keeps the state, so
unbounded writes would grow the wallet's entry past the network limit, and the host would approve
a state that the chain cannot store. The operation denies instead, so no policy write makes every
later standard update fail; operations that write no new key and grow no value still pass at the
bound.
`post_flight` consumes the write buffer first, even when it fails.

The server evaluates a policy with `allowit::evaluate(ctx, execute, tier)`. It clears stale
writes, checks `request.args` with `allowit::check_args` as the wallet kernel does, and, for
`AllowitTier::Standard`, checks the params with `allowit::check_params` as the standard contract
does on every admission. Args or params that the wallet rejects are `InvalidParam`. A standard
wallet can hold a custom param after a code change from Custom, because the new code validates the
kept params only at its next admission. `evaluate` then runs `execute`, and runs `post_flight` on
approval; a denial discards the policy's writes.
So no write outlives its evaluation, also when the server reuses an `AllowitEnv`. Onchain, the
wallet runs `post_flight` after its own policy check, and a denied transaction rolls the temporary
buffer back.

`AllowitTier` selects what a wallet stores. Custom compiles its whole policy, so its
`AllowitTier::Custom` post-flight applies every write. Simple and Common run only the standard
prefix onchain, which never writes, so they never add or change a policy key. Policy keys left by
earlier Custom code stay unchanged and still count toward the bounds. Their
`AllowitTier::Standard` post-flight therefore denies any policy write with `Unsupported`, on the
host as onchain: the server never approves an operation whose state the chain would drop. For every
tier, the state that `evaluate` returns is exactly the state the wallet stores, and the wallet's
`policy_state` alone is the server's next `ctx.state`. `scripts/contract_admin.py` rejects a Simple
or Common packet whose source calls `allowit::set_state`, also through the raw identifier
`allowit::r#set_state`; such a policy needs Custom.

The server-only enrichment functions exist only in the host backend. Each takes the context and an
owner-written request and returns its passing constraint:
`price(ctx, &AllowitPrice { from, to, amount, price, slip })` the observed price,
`fetch(ctx, &AllowitFetch { method, url, data, pubkey })` the verified response,
`internet_search(ctx, &AllowitInternetSearch { query })` and
`marketplace_search(ctx, &AllowitMarketplaceSearch { query })` their results,
`request_screening(ctx, &AllowitRequestScreening { query, deny_below })` the passing score,
`systemone(ctx, &AllowitSystemOne { id, query, deny_below, allow_above })` the passing confidence,
and `clear_systemone_context(ctx)` nothing. Scores and confidences are basis points. There they are
stubs that return `Unsupported` until the server fills them. A Custom policy that calls one does not
compile, because the Soroban backend has none of them.

| Rule and canonical param key | Param value | Pass value |
| --- | --- | --- |
| `transaction_cap` | Nonnegative `Int` gross units for one operation | `cap - amount` |
| `spent_cap` | Nonnegative `Int` cumulative irreversible-expense ceiling | `cap - (spent + spent_units)` |
| `day_spent_cap` | Nonnegative `Int` UTC-day irreversible-expense ceiling | `cap - (today_spent + spent_units)` |
| `day_total_cap` | Nonnegative `Int` UTC-day gross amount plus separate gas | `cap - (today_total + amount + gas_units)` |
| `call_cap` | `Int` in the `u64` range: successful operation count ceiling; zero denies | `cap - (calls + 1)` |
| `recipients` | `List` of `Addr`: permitted destinations, including vaults; empty denies | Matched recipient |
| `tokens` | `List` of `Addr`: exact permitted SAC identities; empty denies | Matched asset |
| `expiry` | `Int` in the `u64` range: exclusive Unix timestamp; request expiry cannot exceed it | `expiry - now` |

`today_spent` and `today_total` are the daily values when `state.day == now / 86400`, and zero for
an earlier day. A later day is `InvalidState`. Each rule checks only the facts it reads. A negative
cap is `InvalidParam`, as are a nonpositive `transaction_cap` amount and negative request units. A negative state value that a cap reads is `InvalidState`. Lifetime unpriced state or an
unpriced request denies `spent_cap`; unpriced state of the day or an unpriced request denies both
daily caps (`Unpriced`). A sum outside its integer range is `Overflow`. Standard configuration
rejects negative caps.

## Standard prefix

The standard prefix is the consecutive leading top-level statements of exactly the form
`allowit::<rule>(ctx, ctx.params.get(allowit::<RULE>))?;`: one canonical rule and its own canonical
key constant. Any other statement ends it, including a rule that reads another key. Later
statements run offchain or in `AllowitCustomPolicy`.
The standard contract receives the exact owner-approved ordered prefix as `rules: Vec<AllowitRule>`, never
caller selectors. `AllowitRule` is a typed enum whose variants are the canonical names. Soroban decodes
vector and map elements when read, so owner configuration decodes every rule and param value before
storing it: an unknown rule name aborts and a malformed element is `InvalidParam`. It runs each call
through `allowit::preflight` as
`if let Some(value) = ctx.params.get(rule.key()) { allowit::<rule>(ctx, Some(value))?; }` and
discards pass values. This preflight runner is the only place an absent param skips its rule. The
offchain full policy and `AllowitCustomPolicy` still run the unguarded call, so they deny it with
`MissingParam`. An absent prefix param is valid configuration: the owner can set or remove params
with `deploy_policy` without code redeployment. `scripts/contract_admin.py` warns about it without
rejecting the packet. The preflight runner propagates the first rule error. Repeated rules
read the same current state and only `post_flight` charges, so a rule cannot charge twice.

Rule denials map to `PolicyDenied`. `MissingParam` and `InvalidParam` map to `InvalidParam`.
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
name; the param it reads is always its canonical key. It excludes param values and full source.
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
With `wasm_hash=None`, params change without code redeployment. Prefix, policy state, custody,
execution nonce and pause remain intact when only params change. The new revision rejects old
inflight packets. A changed prefix or executable requires a new owner binding.

Owner packets bind their exact meaning. Struct decoding ignores extra keys and reads absent
`Option` keys as `None`, so the constructor and `deploy_policy` require owner authorization for
the canonical re-encoding of the decoded packet. A params map decodes as sent, so an absent key is
unset. Bindings name the authored entrypoint `execute`. A packet with legacy, extra or absent keys fails
authorization unless the owner signed that canonical form.

`contract_version` 4 stores `params` and the free-form `policy_state` as key => `AllowitValue`
maps, and `Vec<AllowitRule>`. Version 3 stored the canonical params as a typed struct and policy
state of raw values, version 2 a typed accounting history struct, and version 1 a text-keyed params
map and symbol rules. Execution, `state()`, `policy_state()` and `set_pause` accept only the exact
canonical encoding of version 4. Owner `recover` and `invoke`
decode a typed struct of only the fields they keep, so an in-place upgrade from an earlier layout
never locks recovery. `deploy_policy` carries `policy_state` over; an earlier layout stores none or stores
other values, so `deploy_policy` rejects it with `InvalidState`. No layout migrates implicitly: recover funds from an
earlier layout and deploy a new wallet. A complete typed `deploy_policy` packet replaces params,
rules and roles, keeps policy state, nonce, pause and asset, and writes version 4. Later versions
reject even owner calls, because their kept fields may change meaning. New source and schema
hashes need new owner bindings.

Earlier code reads State only in its own layout, so a `deploy_policy` code change from version 4
to an earlier release permanently locks custody. Each
wallet Wasm declares `allowit_custody_layout` metadata equal to `CONTRACT_VERSION`.
`contract_admin.py` refuses a code change to Wasm that declares another layout or none. Recover
funds before any change across layouts. Every later layout bump needs the same rule.

## Shared engine

`AllowitContext` carries the contract `Env`, so it is not a contract value. The shared engine
exposes each canonical rule as
`<rule>(params: Map<Symbol, AllowitValue>, state: Map<Symbol, AllowitValue>, request: AllowitRequest) -> Result<T, AllowitError>`,
where `state` is the current policy state.
Callers use its generated `AllowitEngineClient`.
It builds the context with its own `Env`, runs `allowit::<rule>(&ctx, ctx.params.get(allowit::<RULE>))`
and returns the same pass value or rule error.
It holds no custody, params or policy state. No policy wallet, release tool or server in this repository
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
configuration version, execution nonce, single-use operation ID and the execution params' bounds
independently of business checks.
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
