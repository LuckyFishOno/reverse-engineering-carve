"""Owned state fixture: preserve one emulated image across a sequence, not Windows execution."""
import hashlib
import json
from pathlib import Path
import struct
import sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_EAX

root = Path(__file__).resolve().parent
payload = sys.stdin.buffer.read(16385)
if len(payload) > 16384:
    raise ValueError("Sequence exceeds input budget")
steps = json.loads(payload)
if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
    raise ValueError("One to64steps required")
for args in steps:
    if not isinstance(args, list) or len(args) != 2 or any(type(n) is not int or n < -(2**31) or n >= 2**31 for n in args):
        raise ValueError("Two signed32arguments required per step")
manifest = json.loads((root / "images.json").read_text())
if manifest["schema"] != "carve/owned-pe-state@1" or len(manifest["images"]) != 1:
    raise ValueError("Owned single-image state fixture required")
image = manifest["images"][0]
if image["file"] != "input/state.exe":
    raise ValueError("Unexpected owned image path")
data = (root / image["file"]).read_bytes()
if len(data) > 2 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != image["sha256"]:
    raise ValueError("Original state image differs from its pin")
m = image["metadata"]
if m["machine"] != 0x8664 or m["sizeOfImage"] != 0x10000 or m["imports"]:
    raise ValueError("Only the owned freestanding x64 state image is supported")
mu = Uc(UC_ARCH_X86, UC_MODE_64)
base = int(m["imageBase"], 0)
mu.mem_map(base, m["sizeOfImage"])
mu.mem_write(base, data[:m["sizeOfHeaders"]])
for s in m["sections"]:
    mu.mem_write(base + s["virtualAddress"], data[s["rawOffset"]:s["rawOffset"] + s["rawSize"]])
mu.mem_protect(base, m["sizeOfImage"], UC_PROT_READ)
for s in m["sections"]:
    flags = s["characteristics"]
    perms = UC_PROT_READ | (UC_PROT_WRITE if flags & 0x80000000 else 0) | (UC_PROT_EXEC if flags & 0x20000000 else 0)
    mu.mem_protect(base + s["virtualAddress"], (max(s["rawSize"], s["virtualSize"]) + 4095) & ~4095, perms)
stop, stack = 0x70000000, 0x70100000
mu.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
mu.mem_map(stack, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
rsp = stack + 0x10000 - 0x108
trace = {"settingsReads": 0, "resourceReads": 0, "counterReads": 0, "counterWrites": 0}
def observe(engine, access, address, size, value, context):
    if base + 0xa000 <= address < base + 0xa014 and access != UC_MEM_WRITE:
        trace["settingsReads"] += 1
    resource = manifest["stringResource"]
    if base + resource["rva"] <= address < base + resource["rva"] + resource["bytes"] and access != UC_MEM_WRITE:
        trace["resourceReads"] += 1
    if base + 0xb000 <= address < base + 0xb004:
        trace["counterWrites" if access == UC_MEM_WRITE else "counterReads"] += 1
mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, observe)
results = []
for args in steps:
    mu.mem_write(rsp, struct.pack("<Q", stop))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RCX, args[0] & 0xffffffff)
    mu.reg_write(UC_X86_REG_RDX, args[1] & 0xffffffff)
    mu.emu_start(int(manifest["entry"], 0), stop, timeout=1000000, count=5000)
    if mu.reg_read(UC_X86_REG_RIP) != stop:
        raise RuntimeError("Original did not return within the declared bounds")
    result = mu.reg_read(UC_X86_REG_EAX)
    results.append({"kind": "return", "value": result if result < 2**31 else result - 2**32})
print(json.dumps({"results": results, "trace": trace} if "--trace" in sys.argv[1:] else results))
