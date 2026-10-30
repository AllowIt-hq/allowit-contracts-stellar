<div align="center">

# Allowit contracts for Stellar

*Policy wallets that let an AI agent spend on Stellar, within limits the owner sets*

[![Validate contracts](https://img.shields.io/github/actions/workflow/status/allowit-hq/allowit-contracts-stellar/contracts.yml?style=flat-square&label=Validate%20contracts)](https://github.com/allowit-hq/allowit-contracts-stellar/actions/workflows/contracts.yml)
[![Rust 1.98.0](https://img.shields.io/badge/Rust-1.98.0-dea584?style=flat-square&logo=rust&logoColor=white)](rust-toolchain.toml)
[![Soroban SDK 28.0.0](https://img.shields.io/badge/Soroban%20SDK-28.0.0-black?style=flat-square)](Cargo.toml)
[![Stellar CLI 28.1.0](https://img.shields.io/badge/Stellar%20CLI-28.1.0-black?style=flat-square)](https://developers.stellar.org/docs/tools/cli/stellar-cli)

[Overview](#overview) • [Three wallets](#three-policy-wallets) • [Roles](#who-holds-which-key) • [How a transfer happens](#how-a-transfer-happens) • [Quick start](#quick-start) • [Operate a wallet](#operate-a-wallet) • [Docs](#documentation)

</div>

**Go on. On your terms.** Allowit lets your AI agents spend and invest, within a policy you set. This repository holds the Soroban smart contracts that enforce that policy on Stellar: owner-controlled wallets that move funds only when the agent and an independent server both sign, and only when the owner's rules say yes.

## Overview

A policy wallet is a Soroban contract that holds one native Stellar asset. The owner decides who may ask it to pay, how much, to whom and until when. Every delegated transfer needs two signatures, the agent's and the server's, and passes the wallet's own policy checks before a single stroop moves. The owner keeps the keys to everything else: pause, reconfigure, recover funds, upgrade the code.

Three wallet implementations share one custody core (`crates/policy-wallet`) and one owner interface. They differ only in where the business rules run.

> [!NOTE]
> Amounts, limits and usage are tracked in the asset's native base units. Only the installed asset can be held and moved. The wallet refuses to pay itself and refuses to pay the asset's issuer, because an issuer payment burns tokens.

## Three policy wallets

| Wallet | Who approves a transfer | Where the rules run |
| --- | --- | --- |
| `SimplePolicyEngine` | Agent and server | Off chain. The server checks the authored policy before it signs. The contract enforces custody invariants only. |
| `CommonPolicyEngine` | Agent and server | On chain, from a canonical rule set. The owner selects an ordered list of rules and the Grant values they read. |
| `CustomPolicy` | Agent and server | On chain, compiled. Bespoke policy source becomes its own contract through the [Allowit SDK](https://github.com/allowit-hq/allowit-sdk), on the same custody mixins. |

Pick **Simple** when your server already runs the whole policy and you want the lightest contract. Pick **Common** when you want standard limits enforced by the ledger itself. Pick **Custom** when the policy needs logic the canonical rules do not cover.

### The canonical rules

Common wallets enforce exactly the rules the owner lists, in that order, and nothing else. An empty list means no on-chain business checks, like Simple. Each rule reads one or two named values from the owner-signed **Grant** and may update the wallet's running **Spent** map.

| Rule | Grant values it reads | What it does |
| --- | --- | --- |
| `transaction_cap` | `per_transfer` | Caps a single transfer |
| `daily_cap` | `daily_limit` | Caps the total per UTC day |
| `total_cap` | `total_limit` | Caps the lifetime total |
| `call_cap` | `max_calls` | Caps the number of transfers; zero denies all |
| `recipient` | `recipients` | Allows only listed addresses; an empty list denies all |
| `expiry` | `expires_at` | Denies from a Unix timestamp on, and requires each request to expire no later than it |
| `token` | `token` | Requires a specific asset label |

The rules live in `crates/rules` and are shared by the Common wallet, compiled Custom policies and the standalone engine contract. Details, value types and Spent keys are in [docs/architecture.md](docs/architecture.md).

## Who holds which key

A wallet knows three addresses, and they must all be different.

- **Owner.** Creates the wallet and signs every configuration change. The owner alone can `deploy_policy`, `set_pause`, `recover` funds and `invoke` any contract call through the wallet. None of these need the agent or the server.
- **Agent.** The AI agent, or whatever acts for you. It co-signs `execute` and nothing else.
- **Server.** An independent signer that co-signs `execute`. It is a second pair of eyes on every transfer, not a shared checker contract and not an administrator.

A separate **engine parent** contract can manage the code of a shared rule-checking engine. It holds no custody authority: it cannot touch a wallet's funds, configuration or signers. See [docs/engine-parent.md](docs/engine-parent.md).

> [!TIP]
> No Soroban contract yet? A classic G-address account can get Simple-style authorization with plain multisig: owner weight 3, agent and server weight 1, thresholds 2/2/3. `scripts/wallet_admin.py` prepares exactly that. Classic reserves still apply, and custom on-chain policy code needs a contract wallet.

## How a transfer happens

1. The agent builds an `ExecutionRequest`: the wallet's policy identity, a fresh operation id, the next nonce, the current deployment version, an expiry, and the exact SEP-41 transfer arguments (`token`, `from`, `to`, `amount`).
2. Agent and server both authorize `execute`.
3. The wallet checks everything before it checks the policy: the installed module, entrypoint and argument schema; canonical argument encoding; the installed asset and the wallet as source; no replay of the operation id; not paused; nonce and deployment version current; not expired; positive amount; recipient is neither the wallet nor the issuer.
4. The wallet runs its local policy (Simple, the selected Common rules, or the compiled Custom code) against the Grant and the current Spent.
5. The token transfer, the new Spent, the nonce and the receipt commit together. A `TransferReceipt` comes back. If anything fails, nothing moves.

### x402 delegation

The owner can enable x402. The agent and the server must then be G-addresses. The wallet acts as a Soroban custom account and verifies both Ed25519 signatures over the host payload and the execution request, then applies the same policy, replay and usage checks as a direct `execute`. The signed context must be exactly one `transfer` on the installed asset.

## Quick start

You need:

- [Rust](https://rustup.rs) with `rustup`. `rust-toolchain.toml` pins Rust 1.98.0 and the `wasm32v1-none` target.
- [Stellar CLI](https://developers.stellar.org/docs/tools/cli/stellar-cli) 28.1.0.
- Python 3.10 or later.
- Git.

```sh
git clone https://github.com/allowit-hq/allowit-contracts-stellar.git
cd allowit-contracts-stellar

python3 scripts/check-policy.py     # verify the portable policy bundle hash
scripts/build-contracts.sh          # reproduce the generated policy and build every Wasm
cargo test --workspace --locked     # authorization and custody regressions
```

The build leaves five contracts in `target/wasm32v1-none/release/`:

```
allowit_simple_policy_engine.wasm
allowit_common_policy_engine.wasm
allowit_custom_policy.wasm
allowit_wallet_engine.wasm
allowit_engine_parent.wasm
```

Write a public manifest of source hashes and artifact hashes with `python3 scripts/artifacts.py --output PATH`.

> [!TIP]
> `scripts/build-contracts.sh` regenerates `crates/custom-policy/src/generated_policy.rs` with the Allowit SDK revision pinned in `scripts/policy-codegen.json` and fails if the bytes differ. It fetches an isolated checkout of that revision unless `ALLOWIT_SDK_PATH` points at a clean checkout of it. `STELLAR_BIN` selects the Stellar CLI executable.

The administration tools need the pinned Python Stellar SDK. Keep it in a virtual environment:

```sh
python3 -m venv /tmp/allowit-admin
/tmp/allowit-admin/bin/pip install -r scripts/requirements-admin.txt
/tmp/allowit-admin/bin/python -m unittest discover -s scripts/tests -v
```

## Operate a wallet

The owner interface is the same on all three wallets:

```
__constructor(config)                         owner
state()                                       anyone
policy_binding()                              anyone
policy_spent()                                anyone
execute(execution)                            agent and server
deploy_policy(deployment)                     owner, plus the new owner if it changes
set_pause(paused, deployment_version)         owner
recover(recipient, amount)                    owner
invoke(contract, function, args, auth)        owner
```

`PolicyConfig` names the `owner`, `agent`, `server`, `asset`, `policy_instance`, `source_digest`, ordered `rules`, `grant` and `x402_enabled`. The asset and the policy identity are fixed for the life of the wallet. Everything else changes through `deploy_policy`, which also accepts an optional new Wasm hash and must target exactly the next `deployment_version`. Pause, Spent and the execution nonce survive every deployment.

`scripts/contract_admin.py` prepares unsigned transactions for `upload`, `deploy-parent`, `deploy-wallet`, `admin` and `read`. It simulates, assembles fees and authorization entries, and hands you XDR to review and sign with your own keys. It never signs, submits or retries. `scripts/wallet_admin.py` does the same for classic accounts (`inspect`, `verify-wallet`, `verify-admin`, `setup-wallet`, `shutdown-wallet`, `setup-admin`).

```sh
python scripts/contract_admin.py read --network testnet --contract "$WALLET" --source "$OWNER" --method policy_binding
```

The step-by-step guide, including Grant encoding and owner handoffs, is in [docs/admin.md](docs/admin.md). Release packets for mainnet are covered in [docs/mainnet.md](docs/mainnet.md).

## Project structure

```
crates/
  protocol/               Shared request, receipt, Grant and Spent types
  rules/                  The seven canonical rules
  policy-wallet/          Custody core, owner operations and the policy_wallet! macro
  simple-policy-engine/   SimplePolicyEngine contract
  common-policy-engine/   CommonPolicyEngine contract
  custom-policy/          CustomPolicy contract with its authored and generated policy
  engine/                 Standalone shared rule engine contract
  engine-parent/          Upgrade parent for the shared engine
policy/                   Portable policy bundle shared byte for byte with the Solana contracts
scripts/                  Build, verification, administration and release tooling
docs/                     Architecture, engine parent, administration, mainnet
```

## Part of Allowit

- [allowit.xyz](https://allowit.xyz) tells the story and holds the official narrative.
- [allowit-sdk](https://github.com/allowit-hq/allowit-sdk) is the policy language, compiler and runtime. Its `stellar-native` target produces the generated policy module in this repository.
- [allowit-contracts-solana](https://github.com/allowit-hq/allowit-contracts-solana) is the Solana sibling. It carries the same `policy/` bundle.
- [allowit-cli](https://github.com/allowit-hq/allowit-cli) is the Go CLI for evaluating and executing actions under a policy.

## Documentation

- [Architecture and authoring](docs/architecture.md): wallets, rules, configuration, x402 and owner operations.
- [Engine parent](docs/engine-parent.md): shared engine state, calls and lifetime.
- [Setup and administration](docs/admin.md): preparing, reviewing and signing wallet transactions.
- [Mainnet preparation](docs/mainnet.md): bounded, unsigned release packets.

## Contributing

Pull requests run the portable policy checks and the chain-free smoke tests. The full Wasm build and `cargo test --workspace --locked` run on a schedule and on demand. Before you open a pull request:

```sh
python3 scripts/check-policy.py
python3 scripts/check-policy-bindings.py
cargo fmt --all --check
scripts/build-contracts.sh
cargo test --workspace --locked
```

Keep contract code, build and API documentation and release inputs here. Planning, reviews and generated evidence live in the Allowit knowledge project, as [AGENTS.md](AGENTS.md) describes.

## License

This repository is published for review. Every crate declares `license = "UNLICENSED"`, so no open-source license is granted.
