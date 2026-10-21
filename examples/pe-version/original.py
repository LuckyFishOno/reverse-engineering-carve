"""Execute pinned third-party PE version exports under an explicit JNI stub.

No DLL initialization, Windows loader, JVM, OS API or archive operation is run.
Only NewStringUTF's ASCII subset is implemented; every other target is unmapped.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RAX

root = Path(__file__).resolve().parent
payload = sys.stdin.buffer.read(4097)
if len(payload) > 4096:
    raise ValueError("Input budget exceeded")
args = json.loads(payload)
manifest = json.loads((root / "images.json").read_text())
if not isinstance(args, list) or len(args) != 1 or args[0] not in manifest["entries"]:
    raise ValueError("One declared version field required")
data = (root / "input/lib7-Zip-JBinding.dll").read_bytes()
if hashlib.sha256(data).hexdigest() != manifest["sha256"]:
    raise ValueError("Original DLL differs from its pin")
m = manifest["metadata"]
if m["machine"] != 0x8664 or m["sizeOfImage"] > 16 * 1024 * 1024:
    raise ValueError("Bounded AMD64 image required")
base = int(m["imageBase"], 0)
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(base, (m["sizeOfImage"] + 4095) & ~4095)
mu.mem_write(base, data[:m["sizeOfHeaders"]])
for section in m["sections"]:
    mu.mem_write(base + section["virtualAddress"], data[section["rawOffset"]:section["rawOffset"] + section["rawSize"]])
mu.mem_protect(base, (m["sizeOfImage"] + 4095) & ~4095, UC_PROT_READ)
for section in m["sections"]:
    flags = section["characteristics"]
    perms = UC_PROT_READ | (UC_PROT_WRITE if flags & 0x80000000 else 0) | (UC_PROT_EXEC if flags & 0x20000000 else 0)
    length = (max(section["rawSize"], section["virtualSize"]) + 4095) & ~4095
    if length:
        mu.mem_protect(base + section["virtualAddress"], length, perms)
stop, stub, env, table, stack, handle = 0x70000000, 0x70001000, 0x70100000, 0x70101000, 0x70200000, 0x70300000
mu.mem_map(stop, 8192, UC_PROT_READ | UC_PROT_EXEC)
mu.mem_map(env, 8192, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(stack, 65536, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_write(env, struct.pack("<Q", table))
mu.mem_write(table + manifest["newStringUtfOffset"], struct.pack("<Q", stub))
trace = {"newStringUtfCalls": 0, "stringAddress": None}
strings = {}
def observe(engine, address, size, context):
    if address != stub:
        return
    if engine.reg_read(UC_X86_REG_RCX) != env:
        raise ValueError("Unexpected JNI environment")
    pointer = engine.reg_read(UC_X86_REG_RDX)
    if not base <= pointer < base + m["sizeOfImage"]:
        raise ValueError("String pointer outside original image")
    text = bytearray()
    for index in range(1024):
        value = engine.mem_read(pointer + index, 1)[0]
        if value == 0:
            break
        if not 32 <= value <= 126:
            raise ValueError("Only printable ASCII JNI strings are modeled")
        text.append(value)
    else:
        raise ValueError("Unterminated JNI string")
    trace["newStringUtfCalls"] += 1
    if trace["newStringUtfCalls"] != 1:
        raise ValueError("Only one JNI allocation is modeled")
    trace["stringAddress"] = hex(pointer)
    strings[handle] = text.decode("ascii")
    sp = engine.reg_read(UC_X86_REG_RSP)
    engine.reg_write(UC_X86_REG_RAX, handle)
    engine.reg_write(UC_X86_REG_RSP, sp + 8)
    engine.reg_write(UC_X86_REG_RIP, struct.unpack("<Q", engine.mem_read(sp, 8))[0])
mu.hook_add(UC_HOOK_CODE, observe)
sp = stack + 65536 - 0x108
mu.mem_write(sp, struct.pack("<Q", stop))
mu.reg_write(UC_X86_REG_RSP, sp)
mu.reg_write(UC_X86_REG_RCX, env)
mu.reg_write(UC_X86_REG_RDX, 0)
mu.emu_start(int(manifest["entries"][args[0]], 0), stop, timeout=1000000, count=1000)
if mu.reg_read(UC_X86_REG_RIP) != stop:
    raise RuntimeError("Original did not return within instruction/time limits")
returned = mu.reg_read(UC_X86_REG_RAX)
is_string = args[0] in ["copyright", "date", "version"]
if trace["newStringUtfCalls"] != int(is_string):
    raise ValueError("Unexpected JNI call count")
value = strings[returned] if is_string else returned & 0xffffffff
print(json.dumps({"value": value, "trace": trace} if "--trace" in sys.argv[1:] else value))
