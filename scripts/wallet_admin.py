#!/usr/bin/env python3
"""Prepare unsigned native-account administration. Never signs or submits."""
import argparse
import json
import sys
import time
from urllib.request import urlopen
from stellar_sdk import Account, Keypair, Network, Signer, TransactionBuilder

HORIZON = {"testnet": "https://horizon-testnet.stellar.org", "mainnet": "https://horizon.stellar.org"}
PASSPHRASE = {"testnet": Network.TESTNET_NETWORK_PASSPHRASE, "mainnet": Network.PUBLIC_NETWORK_PASSPHRASE}


def public(value):
    try:
        Keypair.from_public_key(value)
    except Exception:
        raise argparse.ArgumentTypeError("Expected a public Stellar G address") from None
    return value


def signers(state):
    result = {}
    for entry in state["signers"]:
        key = entry["key"]
        if entry["type"] != "ed25519_public_key" or key in result:
            raise ValueError("Only unique Ed25519 signers are admitted")
        public(key)
        result[key] = entry["weight"]
    return result


def thresholds(state):
    t = state["thresholds"]
    return tuple(t[key] for key in ("low_threshold", "med_threshold", "high_threshold"))


def owner_only(state):
    """Admit a native master-key owner, never an agent/evaluator quorum."""
    account = public(state["account_id"])
    active = []
    for signer in state["signers"]:
        weight = signer["weight"]
        if type(weight) is not int or not 0 <= weight <= 255:
            raise ValueError("Invalid signer weight")
        if weight > 0:
            active.append(signer)
    if len(active) != 1 or active[0]["type"] != "ed25519_public_key" or active[0]["key"] != account:
        raise ValueError("Policy wallet owner must have only its master key active; delegated native quorums are unsafe")
    weight = active[0]["weight"]
    if any(type(t) is not int or not 0 <= t <= weight for t in thresholds(state)):
        raise ValueError("Owner thresholds must remain satisfiable by its master key")
    return account


def fresh(state):
    account = public(state["account_id"])
    if signers(state) != {account: 1} or thresholds(state) != (0, 0, 0):
        raise ValueError("Setup requires an existing fresh account with only master weight 1 and default thresholds")


def wallet(state, agent, engine):
    account = public(state["account_id"])
    if len({account, public(agent), public(engine)}) != 3:
        raise ValueError("Owner, agent and engine must differ")
    expected = {account: 3, agent: 1, engine: 1}
    if signers(state) != expected or thresholds(state) != (2, 2, 3):
        raise ValueError("Account is not the exact owner/agent/engine 3/1/1 profile")
    return expected


def admin(state, members):
    members = [public(key) for key in members]
    if len(set(members)) != 3:
        raise ValueError("Three distinct admin members are required")
    expected = dict.fromkeys(members, 1)
    expected.setdefault(state["account_id"], 0)
    if signers(state) != expected or thresholds(state) != (2, 2, 2):
        raise ValueError("Account is not the exact three-member 2-of-3 profile")
    return expected


def prepare(state, action, network, *, agent=None, engine=None, members=None, fee=100, now=None, source_state=None):
    if network not in PASSPHRASE:
        raise ValueError("Unsupported network")
    if not 100 <= fee <= 100_000:
        raise ValueError("Fee must be 100..100000 stroops per operation")
    account = public(state["account_id"])
    if source_state is not None:
        if action != "shutdown-wallet" or source_state["account_id"] in (account, agent, engine):
            raise ValueError("A separate transaction source is supported only for shutdown")
        owner_only(source_state)
    sequence = int((source_state or state)["sequence"])
    if sequence < 0:
        raise ValueError("Negative sequence")
    now = int(time.time()) if now is None else now
    builder = TransactionBuilder(Account((source_state or state)["account_id"], sequence), PASSPHRASE[network], base_fee=fee)
    builder.add_time_bounds(0, now + 300)
    if action == "setup-wallet":
        fresh(state)
        if len({account, public(agent), public(engine)}) != 3:
            raise ValueError("Owner, agent and engine must differ")
        builder.append_set_options_op(signer=Signer.ed25519_public_key(agent, 1))
        builder.append_set_options_op(signer=Signer.ed25519_public_key(engine, 1))
        builder.append_set_options_op(master_weight=3, low_threshold=2, med_threshold=2, high_threshold=3)
    elif action == "shutdown-wallet":
        wallet(state, agent, engine)
        builder.append_set_options_op(signer=Signer.ed25519_public_key(agent, 0))
        builder.append_set_options_op(signer=Signer.ed25519_public_key(engine, 0))
        builder.append_set_options_op(master_weight=3, low_threshold=3, med_threshold=3, high_threshold=3)
    elif action == "setup-admin":
        fresh(state)
        members = [public(key) for key in members or []]
        if len(set(members)) != 3 or len(members) != 3:
            raise ValueError("Three distinct admin members are required")
        for key in members:
            if key != account:
                builder.append_set_options_op(signer=Signer.ed25519_public_key(key, 1))
        builder.append_set_options_op(master_weight=int(account in members), low_threshold=2, med_threshold=2, high_threshold=2)
    else:
        raise ValueError("Unsupported preparation action")
    envelope = builder.build()
    if source_state is not None:
        from stellar_sdk import MuxedAccount
        for operation in envelope.transaction.operations:
            operation.source = MuxedAccount(account)
    return envelope


def fetch(network, account):
    with urlopen(HORIZON[network] + "/accounts/" + public(account), timeout=20) as response:
        state = json.load(response)
    if state["account_id"] != account:
        raise ValueError("Account response mismatch")
    return state


def no_offers(network, account, reject=True):
    with urlopen(HORIZON[network] + "/accounts/" + public(account) + "/offers?limit=1", timeout=20) as response:
        offers = json.load(response)
    if offers["_embedded"]["records"]:
        if reject:
            raise ValueError("Open offers prevent native-wallet verification")
        print("Warning: open offers remain. Revoke signers first, then reconcile offers and allowances.", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["inspect", "verify-wallet", "verify-admin", "setup-wallet", "shutdown-wallet", "setup-admin"])
    p.add_argument("--network", choices=HORIZON, default="testnet")
    p.add_argument("--allow-mainnet", action="store_true", help="Explicitly permit mainnet preparation (never submission)")
    p.add_argument("--account", required=True, type=public, help="Existing account; native wallet owner is its master key")
    p.add_argument("--agent", type=public)
    p.add_argument("--engine", type=public)
    p.add_argument("--member", action="append", default=[], type=public)
    p.add_argument("--transaction-source", type=public, help="Separate owner-only fee/sequence account, for shutdown only")
    p.add_argument("--fee", type=int, default=100, help="Inclusion fee in stroops per operation")
    args = p.parse_args()
    if args.network == "mainnet" and args.action.startswith(("setup", "shutdown")) and not args.allow_mainnet:
        p.error("Mainnet preparation requires --allow-mainnet")
    if args.action in ("setup-wallet", "shutdown-wallet", "verify-wallet") and not (args.agent and args.engine):
        p.error("--agent and --engine are required")
    if args.transaction_source and args.action != "shutdown-wallet":
        p.error("--transaction-source is supported only for shutdown")
    state = fetch(args.network, args.account)
    if args.action in ("verify-wallet", "shutdown-wallet"):
        no_offers(args.network, args.account, reject=args.action == "verify-wallet")
    if args.action == "inspect":
        print(json.dumps({key: state[key] for key in ("account_id", "sequence", "signers", "thresholds")}, indent=2))
    elif args.action == "verify-wallet":
        wallet(state, args.agent, args.engine)
        print("Exact native wallet profile verified")
    elif args.action == "verify-admin":
        admin(state, args.member)
        print("Exact engine administrator profile verified")
    else:
        print(prepare(state, args.action, args.network, agent=args.agent, engine=args.engine,
                      members=args.member, fee=args.fee, source_state=fetch(args.network, args.transaction_source) if args.transaction_source else None).to_xdr())


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, argparse.ArgumentTypeError) as error:
        raise SystemExit(str(error)) from None
