#!/usr/bin/env python3
"""Deploy fresh contracts and exercise actual Stellar Testnet token transfers.

Requires funded secure-store identities: allowit-native-owner/executor/recipient.
Only uses the hardcoded Stellar Testnet. Never prints or reads private keys.
"""
import hashlib, json, os, re, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = os.environ.get("STELLAR_BIN", "stellar")
OWNER = "allowit-native-owner"
EXECUTOR = "allowit-native-executor"
RECIPIENT = "allowit-native-recipient"
OUT = ROOT / "private" / f"testnet-{int(time.time())}"
OUT.mkdir(parents=True, mode=0o700)
evidence = {"network": "stellar:testnet", "passphrase": "Test SDF Network ; September 2015", "source_hash": subprocess.check_output(["python3",str(ROOT/"scripts/check-policy.py")],text=True).strip(), "operations": []}

def run(label, args, expect_failure=False):
    r = subprocess.run([CLI, *args], cwd=ROOT, text=True, capture_output=True, timeout=120)
    hashes = re.findall(r"\b[0-9a-f]{64}\b", r.stderr)
    evidence["operations"].append({"label":label,"success":r.returncode==0,"transaction_candidates":hashes,"result":r.stdout.strip(),"diagnostic":r.stderr[-3000:]})
    (OUT/"evidence.json").write_text(json.dumps(evidence, indent=2))
    if expect_failure:
        assert r.returncode != 0, f"{label} unexpectedly succeeded"
        print(label+": rejected")
        return None
    if r.returncode:
        raise RuntimeError(label+": "+r.stderr)
    print(label+": passed")
    return r.stdout.strip()

def invoke(label, contract, method, args=(), signer=OWNER, failure=False, read=False):
    return run(label,["contract","invoke","--id",contract,"--network","testnet","--source",signer,"--send",("no" if read else "yes"),"--",method,*args], failure)

owner = run("owner address", ["keys","address",OWNER])
recipient = run("recipient address", ["keys","address",RECIPIENT])
executor = run("executor address", ["keys","address",EXECUTOR])
asset = run("native asset", ["contract","id","asset","--asset","native","--network","testnet"])
hashes = {}
for name in ["policy","vault","factory"]:
    wasm = ROOT/f"target/wasm32v1-none/release/allowit_{name}.wasm"
    evidence[name+"_artifact"]={"sha256":hashlib.sha256(wasm.read_bytes()).hexdigest(),"bytes":wasm.stat().st_size}
    hashes[name]=run("upload "+name,["contract","upload","--wasm",str(wasm),"--network","testnet","--source",OWNER])
policy=run("deploy policy",["contract","deploy","--wasm-hash",hashes["policy"],"--network","testnet","--source",OWNER])
factory=run("deploy factory",["contract","deploy","--wasm-hash",hashes["factory"],"--network","testnet","--source",OWNER,"--","--vault_wasm",hashes["vault"]])
salt=hashlib.sha256(str(time.time_ns()).encode()).hexdigest()
vault=json.loads(invoke("factory creates vault",factory,"create",["--salt",salt,"--owner",owner,"--executor",executor,"--asset",asset,"--policy",policy,"--policy_source",evidence["source_hash"],"--policy_wasm",hashes["policy"],"--daily_limit","1000000"]))
evidence.update({"owner":owner,"executor":executor,"recipient":recipient,"asset":asset,"policy":policy,"factory":factory,"vault":vault})
recipient_before=int(json.loads(invoke("recipient initial balance",asset,"balance",["--id",recipient],read=True)))
invoke("deposit 2 XLM",vault,"deposit",["--from",owner,"--amount","2000000"])
invoke("unapproved transfer",vault,"transfer",["--recipient",recipient,"--amount","1","--nonce","0","--expected_revision","0"],EXECUTOR,True)
invoke("approve policy",vault,"approve",["--approved","true","--expected_revision","0"])
invoke("transfer 0.6 XLM",vault,"transfer",["--recipient",recipient,"--amount","600000","--nonce","0","--expected_revision","1"],EXECUTOR)
state=json.loads(invoke("state after transfer",vault,"state",read=True))
assert int(state["spent"])==600000 and int(state["nonce"])==1
invoke("deny daily excess",vault,"transfer",["--recipient",recipient,"--amount","500000","--nonce","1","--expected_revision","1"],EXECUTOR,True)
invoke("deny nonce replay",vault,"transfer",["--recipient",recipient,"--amount","1","--nonce","0","--expected_revision","1"],EXECUTOR,True)
invoke("deny unauthorized tuning",vault,"set_daily_limit",["--value","2000000","--expected_revision","1"],EXECUTOR,True)
invoke("deny tuning outside compiled bound",vault,"set_daily_limit",["--value","50000001","--expected_revision","1"],failure=True)
invoke("tune daily limit",vault,"set_daily_limit",["--value","2000000","--expected_revision","1"])
state=json.loads(invoke("counter preserved by tuning",vault,"state",read=True))
assert int(state["spent"])==600000
invoke("deny old parameter revision",vault,"transfer",["--recipient",recipient,"--amount","1","--nonce","1","--expected_revision","1"],EXECUTOR,True)
invoke("transfer with current revision",vault,"transfer",["--recipient",recipient,"--amount","500000","--nonce","1","--expected_revision","2"],EXECUTOR)
invoke("revoke policy",vault,"approve",["--approved","false","--expected_revision","2"])
invoke("deny revoked transfer",vault,"transfer",["--recipient",recipient,"--amount","1","--nonce","2","--expected_revision","3"],EXECUTOR,True)
invoke("unsupported method",vault,"unsupported",["--method","1"],failure=True)
invoke("recover remaining funds",vault,"withdraw",["--amount","900000"])
assert int(json.loads(invoke("empty vault",vault,"balance",read=True)))==0
recipient_after=int(json.loads(invoke("recipient settled balance",asset,"balance",["--id",recipient],read=True)))
assert recipient_after-recipient_before==11_000_000
evidence["recipient_delta_stroops"]=recipient_after-recipient_before
evidence["complete"]=True
(OUT/"evidence.json").write_text(json.dumps(evidence,indent=2))
print("Evidence:",OUT/"evidence.json")
