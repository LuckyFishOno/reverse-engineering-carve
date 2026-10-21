"""Owned PE function harness: explicit x64 ABI/IAT mapping, never a Windows OS loader."""
import hashlib
import json
from pathlib import Path
import struct
import sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_EAX

root = Path(__file__).resolve().parent
payload = sys.stdin.buffer.read(8193)
if len(payload) > 8192:
    raise ValueError("Input exceeds fixture budget")
args = json.loads(payload)
if not isinstance(args, list) or len(args) != 2 or any(type(n) is not int or n < -(2**31) or n >= 2**31 for n in args):
    raise ValueError("Two signed32 integer arguments required")
manifest = json.loads((root / "images.json").read_text())
if manifest["schema"] != "carve/owned-pe-behavior@1" or len(manifest["images"]) != 2:
    raise ValueError("This harness accepts only its owned two-image fixture")
mu = Uc(UC_ARCH_X86, UC_MODE_64)
exports = {}
for image in manifest["images"]:
    relative = Path(image["file"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Image paths must be owned relative paths")
    data = (root / relative).read_bytes()
    if len(data) > 2 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != image["sha256"]:
        raise ValueError("Original image differs from its pin")
    m = image["metadata"]
    base = int(m["imageBase"], 0)
    if m["machine"] != 0x8664 or m["sizeOfImage"] > 0x100000:
        raise ValueError("Owned x64 PE fixture required")
    mu.mem_map(base, (m["sizeOfImage"] + 0xFFF) & ~0xFFF)
    mu.mem_write(base, data[:m["sizeOfHeaders"]])
    for section in m["sections"]:
        start, size = section["rawOffset"], section["rawSize"]
        mu.mem_write(base + section["virtualAddress"], data[start:start + size])
    mu.mem_protect(base, (m["sizeOfImage"] + 0xFFF) & ~0xFFF, UC_PROT_READ)
    for section in m["sections"]:
        flags = section["characteristics"]
        perms = UC_PROT_READ | (UC_PROT_WRITE if flags & 0x80000000 else 0) | (UC_PROT_EXEC if flags & 0x20000000 else 0)
        mu.mem_protect(base + section["virtualAddress"], (max(section["rawSize"], section["virtualSize"]) + 0xFFF) & ~0xFFF, perms)
    for exported in (m["exports"] or {}).get("entries", []):
        if "forwarder" in exported:
            raise ValueError("Forwarded exports are outside this fixture")
        for name in exported["names"]:
            exports[(relative.name.lower(), name)] = base + exported["rva"]
for image in manifest["images"]:
    m = image["metadata"]
    for module in m["imports"]:
        if module["kind"] != "import":
            raise ValueError("Delay imports are outside this fixture runtime")
        for entry in module["entries"]:
            address = exports[(module["name"].lower(), entry["name"])]
            mu.mem_write(int(m["imageBase"], 0) + entry["thunkRva"], struct.pack("<Q", address))
stop, stack = 0x70000000, 0x70100000
mu.mem_map(stop, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
mu.mem_map(stack, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
rsp = stack + 0x100000 - 0x1008
mu.mem_write(rsp, struct.pack("<Q", stop))
mu.reg_write(UC_X86_REG_RSP, rsp)
mu.reg_write(UC_X86_REG_RCX, args[0] & 0xFFFFFFFF)
mu.reg_write(UC_X86_REG_RDX, args[1] & 0xFFFFFFFF)
visited = {name: 0 for name in ["entry", "blocks", "rate"]}
addresses = {int(manifest[name], 0): name for name in visited}
def observe(engine, address, size, context):
    if address in addresses:
        visited[addresses[address]] += 1
mu.hook_add(UC_HOOK_CODE, observe)
mu.emu_start(int(manifest["entry"], 0), stop, timeout=1000000, count=5000)
if mu.reg_read(UC_X86_REG_RIP) != stop:
    raise RuntimeError("Original did not return within the instruction/time limit")
value = mu.reg_read(UC_X86_REG_EAX)
if value >= 2**31:
    value -= 2**32
print(json.dumps({"value": value, "visited": visited} if "--trace" in sys.argv[1:] else value))
