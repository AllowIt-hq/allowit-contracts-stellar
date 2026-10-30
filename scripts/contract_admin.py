#!/usr/bin/env python3
"""Prepare explicit Stellar contract setup/admin XDR. Never signs or submits."""
import argparse
import copy
import hashlib
import time
import json
import os
import re
import subprocess
from pathlib import Path
from stellar_sdk import Address, Network, xdr, StrKey, TransactionEnvelope, InvokeHostFunction, Preconditions, TimeBounds
from wallet_admin import admin as verify_admin, fetch, owner_only, PASSPHRASE

# No transfers, token approvals, general calls or arbitrary method dispatch.
WALLET = {
    "deploy_policy": {"deployment"},
    "set_pause": {"paused", "deployment_version"},
    "recover": {"recipient", "amount"},
}

PARENT = {
    "upgrade_engine": {"new_hash", "version"},
    "upgrade_parent": {"new_hash", "version"},
    "set_admin": {"owner", "version"},
}


def public_json(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("Duplicate public JSON key")
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=unique)


def address(value):
    if not isinstance(value, str) or not (StrKey.is_valid_ed25519_public_key(value) or StrKey.is_valid_contract(value)):
        raise ValueError("Expected a public Stellar G or C address")
    return value


def account(value):
    try:
        valid = isinstance(value, str) and StrKey.is_valid_ed25519_public_key(value)
    except Exception:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError("Expected a public Stellar G address")
    return value


def contract(value):
    if not isinstance(value, str) or not StrKey.is_valid_contract(value):
        raise ValueError("Expected a contract C address")
    return value


def code_hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("Expected 32-byte hexadecimal Wasm hash")
    return value


def pinned_wasm(path, expected_hash):
    expected_hash = code_hash(expected_hash).lower()
    if not path:
        raise ValueError("Constructor deployment requires --wasm and its pinned --wasm-hash")
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected_hash:
        raise ValueError("Local Wasm does not match the pinned deployment hash")
    return expected_hash


# Typed Grant fields, which are also the canonical rule names. Unset fields are null.
GRANT_FIELDS = ("transaction_cap", "spent_cap", "day_spent_cap", "day_total_cap", "call_cap", "recipients", "tokens", "expiry")
CAPS = {"transaction_cap", "spent_cap", "day_spent_cap", "day_total_cap"}
LISTS = {"recipients", "tokens"}


def grant(value):
    """Validate a typed Grant and return all fields in canonical order. Missing fields are null."""
    if not isinstance(value, dict) or any(name not in GRANT_FIELDS for name in value):
        raise ValueError("Grant fields must be canonical rule names: " + ", ".join(GRANT_FIELDS))
    result = {}
    for name in GRANT_FIELDS:
        item = value.get(name)
        if item is None:
            pass
        elif name in LISTS:
            if not isinstance(item, list):
                raise ValueError("Grant " + name + " must be a list of addresses")
            for entry in item:
                address(entry)
        elif type(item) is not int or not 0 <= item <= (2**127 - 1 if name in CAPS else 2**64 - 1):
            raise ValueError("Grant " + name + " must be a nonnegative native integer")
        result[name] = item
    return result


def grant_cli(value):
    # Pinned CLI spec JSON: Option is null or its value; i128 as a decimal string avoids float decoding.
    return {name: str(item) if name in CAPS and item is not None else item for name, item in grant(value).items()}


def deployment(value):
    fields = {"deployment_version", "owner", "agent", "server", "source_digest", "rules", "grant", "x402_enabled", "wasm_hash"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Deployment fields must exactly match the policy wallet ABI")
    if type(value["deployment_version"]) is not int or not 0 < value["deployment_version"] < 2**64:
        raise ValueError("Invalid deployment version")
    for role in ("owner", "agent", "server"):
        address(value[role])
    grant(value["grant"])
    code_hash(value["source_digest"])
    if not isinstance(value["rules"], list) or any(rule not in GRANT_FIELDS for rule in value["rules"]):
        raise ValueError("Rules must name canonical rules: " + ", ".join(GRANT_FIELDS))
    if type(value["x402_enabled"]) is not bool:
        raise ValueError("x402_enabled must be boolean")
    if value["x402_enabled"] and any(not StrKey.is_valid_ed25519_public_key(value[role]) for role in ("agent", "server")):
        raise ValueError("x402 requires native G-agent and G-server signers")
    for name in ("wasm_hash",):
        if value[name] is not None:
            code_hash(value[name])
    return value


def checked_args(method, values, family):
    expected = (WALLET if family == "wallet" else PARENT)[method]
    if not isinstance(values, dict) or set(values) != expected:
        raise ValueError("Arguments must exactly match " + ", ".join(sorted(expected)))
    for key, value in values.items():
        if key == "deployment":
            deployment(value)
        elif key == "deployment_version":
            if type(value) is not int or not 0 < value < 2**64:
                raise ValueError("Invalid deployment version")
        elif key == "version" or key == "amount":
            if type(value) is not int or (value < 0 if key == "version" else value <= 0) or value > (2**64 - 1 if key == "version" else 2**127 - 1):
                raise ValueError("Invalid integer " + key)
        elif key in ("new_wasm_hash", "new_hash"):
            code_hash(value)
        elif key == "paused":
            if type(value) is not bool:
                raise ValueError("paused must be boolean")
        elif key in ("new_owner", "agent", "owner"):
            account(value)
        elif key == "engine":
            contract(value)
        elif key == "grant":
            grant(value)
        else:
            address(value)
    return values


def serialize(values):
    args = []
    for key, value in values.items():
        if key in ("deployment", "config"):
            value = copy.deepcopy(value)
            value["grant"] = grant_cli(value["grant"])
        elif key == "grant":
            value = grant_cli(value)
        args += ["--" + key.replace("_", "-"), json.dumps(value, separators=(",", ":")) if not isinstance(value, str) else value]
    return args


def cli_run(args, input_data=None):
    # Ignore inherited Stellar signing/source/network overrides. No secret inputs.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("STELLAR_")}
    cli = os.environ.get("STELLAR_BIN", "stellar")
    version = subprocess.run([cli, "--version"], check=True, capture_output=True, text=True, env=environment).stdout
    if not version.startswith("stellar 28.1.0 "):
        raise ValueError("Stellar CLI 28.1.0 is required")
    return subprocess.run([cli] + args, check=True, capture_output=True, text=True, env=environment, input=input_data).stdout.strip()


def prepare_xdr(raw_xdr, source, network, now=None, max_fee=10_000_000, candidate=None, expected_wasm=None):
    """Assemble RPC resources without permitting transaction-intent changes."""
    raw = TransactionEnvelope.from_xdr(raw_xdr, PASSPHRASE[network])
    tx = raw.transaction
    if raw.signatures or not tx.v1 or tx.source.account_id != source or tx.source.account_muxed_id is not None:
        raise ValueError("Expected unsigned v1 transaction with the selected native source")
    if len(tx.operations) != 1 or not isinstance(tx.operations[0], InvokeHostFunction):
        raise ValueError("Expected exactly one Soroban host-function operation")
    if expected_wasm is not None:
        host = tx.operations[0].host_function
        if host.type != xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2 or host.create_contract_v2.executable.type != xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM or host.create_contract_v2.executable.wasm_hash.hash.hex() != code_hash(expected_wasm).lower():
            raise ValueError("Deployment transaction does not use the pinned Wasm executable")
    operation_source = tx.operations[0].source
    if operation_source is not None and operation_source.to_xdr_object() != tx.source.to_xdr_object():
        raise ValueError("Operation source differs from selected transaction source")
    now = int(time.time()) if now is None else now
    if tx.preconditions is None:
        tx.preconditions = Preconditions()
    tx.preconditions.time_bounds = TimeBounds(0, now + 300)
    simulation = ["tx", "simulate", "--network", network, "--source-account", source, "--auth-mode", "root"]
    assembled_xdr = cli_run(simulation, input_data=raw.to_xdr())
    assembled = TransactionEnvelope.from_xdr(assembled_xdr, PASSPHRASE[network])
    result = assembled.transaction
    if assembled.signatures or not result.v1 or result.soroban_data is None:
        raise ValueError("Simulation must return unsigned assembled Soroban XDR")
    if len(result.operations) != 1 or not isinstance(result.operations[0], InvokeHostFunction):
        raise ValueError("Simulation changed the operation shape")
    if type(max_fee) is not int or max_fee <= 0 or result.fee > max_fee or result.soroban_data.resource_fee.int64 > max_fee:
        raise ValueError("Simulated fee exceeds the explicitly selected ceiling")
    validate_auth(result.operations[0], candidate, network)
    # Simulation may add authorization, resources/footprint and their fee only.
    normalized = copy.deepcopy(result)
    normalized.fee = tx.fee
    normalized.soroban_data = tx.soroban_data
    normalized.operations[0].auth = tx.operations[0].auth
    if normalized.to_xdr_object().to_xdr() != tx.to_xdr_object().to_xdr() or result.fee < tx.fee:
        raise ValueError("Simulation changed transaction intent")
    return assembled.to_xdr()


def deployment_address(create, network):
    preimage = xdr.HashIDPreimage(
        xdr.EnvelopeType.ENVELOPE_TYPE_CONTRACT_ID,
        contract_id=xdr.HashIDPreimageContractID(xdr.Hash(Network(PASSPHRASE[network]).network_id()), create.contract_id_preimage))
    return Address(StrKey.encode_contract(hashlib.sha256(preimage.to_xdr_bytes()).digest())).to_xdr_sc_address()


def validate_auth(operation, candidate=None, network="testnet"):
    host = operation.host_function
    allowed_types = {
        xdr.HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT: (xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN, "invoke_contract", "contract_fn"),
        xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT: (xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_HOST_FN, "create_contract", "create_contract_host_fn"),
        xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2: (xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_V2_HOST_FN, "create_contract_v2", "create_contract_v2_host_fn"),
    }
    seen_source = False
    seen_candidate = False
    for entry in operation.auth:
        root = entry.root_invocation
        kind = allowed_types.get(host.type)
        if kind is None or root.function.type != kind[0] or getattr(root.function, kind[2]) != getattr(host, kind[1]):
            raise ValueError("Simulation requested unexpected authorization scope")
        credentials = entry.credentials
        if host.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2:
            if credentials.type != xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT or len(root.sub_invocations) != 1:
                raise ValueError("Deployment requires one exact source-authorized constructor child")
            child = root.sub_invocations[0]
            constructor = child.function.contract_fn
            if child.sub_invocations or child.function.type != xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN or constructor is None:
                raise ValueError("Unexpected deployment constructor authorization shape")
            if constructor.contract_address != deployment_address(host.create_contract_v2, network) or constructor.function_name.sc_symbol != b"__constructor" or constructor.args != host.create_contract_v2.constructor_args:
                raise ValueError("Deployment constructor authorization does not match its preimage and arguments")
        elif root.sub_invocations:
            raise ValueError("Invocation authorization must not contain children")
        if credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT:
            if seen_source:
                raise ValueError("Duplicate source authorization")
            seen_source = True
        elif credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS:
            if not candidate or seen_candidate or credentials.address.address != Address(candidate).to_xdr_sc_address():
                raise ValueError("Simulation requested an unexpected authorization address")
            if credentials.address.signature.type != xdr.SCValType.SCV_VOID:
                raise ValueError("Simulation supplied unexpected authorization signatures")
            seen_candidate = True
        else:
            raise ValueError("Unsupported authorization credential type")
    if host.type == xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2 and not seen_source:
        raise ValueError("Deployment requires source-account constructor authorization")


def command(args):
    if args.network == "mainnet" and not args.allow_mainnet and args.action != "read":
        raise ValueError("Mainnet preparation requires --allow-mainnet")
    base = ["--network", args.network, "--source-account", account(args.source)]
    if args.action == "upload":
        if not args.wasm:
            raise ValueError("--wasm is required")
        return ["contract", "upload", "--wasm", args.wasm, "--build-only"] + base
    if args.action.startswith("deploy-"):
        pinned_wasm(args.wasm, args.wasm_hash)
        if args.action == "deploy-parent":
            values = {"owner": address(args.owner), "engine_wasm": code_hash(args.engine_wasm)}
            if args.source != args.owner:
                raise ValueError("Parent deployment source must be its native admin account")
        else:
            config = public_json(args.config)
            fields = {"owner", "agent", "server", "asset", "policy_instance", "source_digest", "rules", "grant", "x402_enabled"}
            if not isinstance(config, dict) or set(config) != fields:
                raise ValueError("Config fields must exactly match the policy wallet ABI")
            deployment({key: config[key] for key in fields - {"asset", "policy_instance"}} | {"deployment_version": 1, "wasm_hash": None})
            contract(config["asset"])
            code_hash(config["policy_instance"])
            if int(config["policy_instance"], 16) == 0 or int(config["source_digest"], 16) == 0:
                raise ValueError("Policy and source identities must be nonzero")
            if args.source != config["owner"]:
                raise ValueError("Policy wallet deployment source must be its owner")
            if len({config[key] for key in ("owner", "agent", "server")}) != 3:
                raise ValueError("Owner, agent and server must differ")
            values = {"config": config}
        return ["contract", "deploy", "--wasm", args.wasm, "--build-only"] + base + ["--"] + serialize(values)
    address(args.contract)
    if not StrKey.is_valid_contract(args.contract):
        raise ValueError("Target must be a contract C address")
    if args.action == "read":
        if args.method not in ("state", "engine", "policy_binding"):
            raise ValueError("Only state, engine and policy_binding reads are supported")
        return ["contract", "invoke", "--id", args.contract, "--send=no"] + base + ["--", args.method]
    methods = WALLET if args.family == "wallet" else PARENT
    if args.method not in methods:
        raise ValueError("Method is outside the admin allowlist")
    values = checked_args(args.method, public_json(args.arguments), args.family)
    return ["contract", "invoke", "--id", args.contract, "--build-only"] + base + ["--", args.method] + serialize(values)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["upload", "deploy-parent", "deploy-wallet", "read", "admin"])
    p.add_argument("--network", choices=["testnet", "mainnet"], default="testnet")
    p.add_argument("--allow-mainnet", action="store_true")
    p.add_argument("--source", required=True, type=account)
    for flag in ("wasm", "wasm-hash", "engine-wasm", "owner", "agent", "engine", "asset", "grant", "policy-instance", "config", "contract", "method"):
        p.add_argument("--" + flag)
    p.add_argument("--family", choices=["wallet", "parent"], default="wallet")
    p.add_argument("--member", action="append", default=[], type=account, help="Exactly three public members of the native parent admin")
    p.add_argument("--candidate-member", action="append", default=[], type=account, help="Three admitted members for parent admin handoff candidate")
    p.add_argument("--max-fee", type=int, default=10_000_000, help="Maximum total/resource fee in stroops; default 1 XLM")
    p.add_argument("--arguments", default="{}", help="Public argument JSON; never keys or credentials")
    args = p.parse_args()
    prepared = command(args)
    if args.action == "deploy-parent" or args.action == "admin" and args.family == "parent":
        verify_admin(fetch(args.network, args.source), args.member)
        if args.action == "admin" and args.method == "set_admin":
            verify_admin(fetch(args.network, public_json(args.arguments)["owner"]), args.candidate_member)
    if args.action == "deploy-wallet" or args.action == "admin" and args.family == "wallet":
        owner_only(fetch(args.network, args.source))

    if args.action == "admin":
        state_args = ["contract", "invoke", "--id", args.contract, "--network", args.network,
                      "--source-account", args.source, "--send=no", "--", "state"]
        state = json.loads(cli_run(state_args))
        authority = state["owner"]
        if args.family == "wallet":
            values = public_json(args.arguments)
            if args.method == "deploy_policy":
                policy = values["deployment"]
                roles = {key: policy[key] for key in ("owner", "agent", "server")}
                if len(set(roles.values())) != 3 or args.contract in roles.values():
                    raise ValueError("Owner, agent, server and policy wallet must be distinct")
                if roles["owner"] != state["owner"]:
                    owner_only(fetch(args.network, account(roles["owner"])))
        if args.source != authority:
            raise ValueError("Source is not the contract's current owner/admin")
        values = public_json(args.arguments)
        if args.family == "parent":
            if values["version"] != state["version"]:
                raise ValueError("Expected version does not match current state")
        elif args.method != "recover":
            target = values["deployment"]["deployment_version"] if args.method == "deploy_policy" else values["deployment_version"]
            if target != state["deployment_version"] + 1:
                raise ValueError("Policy deployment must use the next version")
    output = cli_run(prepared)
    candidate = None
    if args.action == "admin" and args.method == "set_admin":
        candidate = public_json(args.arguments)["owner"]
    elif args.action == "admin" and args.method == "deploy_policy":
        next_owner = public_json(args.arguments)["deployment"]["owner"]
        if next_owner != authority:
            candidate = next_owner
    print(output if args.action == "read" else prepare_xdr(output, args.source, args.network, max_fee=args.max_fee, candidate=candidate, expected_wasm=args.wasm_hash if args.action.startswith("deploy-") else None))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, argparse.ArgumentTypeError) as error:
        raise SystemExit(str(error)) from None
