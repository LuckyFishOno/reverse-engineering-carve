"""Pinned third-party CrcUpdateT1 under an explicit uint32/buffer/table ABI.
No original table generator, DLL initializer, Windows loader or OS APIs execute.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RIP, UC_X86_REG_EAX
root = Path(__file__).resolve().parent
payload = sys.stdin.buffer.read(32769)
if len(payload) > 32768:
    raise ValueError("Input budget exceeded")
args = json.loads(payload)
def uint32(value):
    return type(value) is int and 0 <= value <= 0xffffffff
if not isinstance(args, list) or len(args) != 3:
    raise ValueError("State, byte array and explicit table required")
state, values, table_values = args
if not uint32(state) or not isinstance(values, list) or len(values) > 4096 or any(type(v) is not int or not 0 <= v <= 255 for v in values):
    raise ValueError("Bounded uint32 state and byte array required")
if not isinstance(table_values, list) or len(table_values) != 256 or any(not uint32(v) for v in table_values):
    raise ValueError("Exactly256uint32table entries required")
manifest = json.loads((root / "images.json").read_text())
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
stop, stack, buffer, table = 0x70000000, 0x70100000, 0x70200000, 0x70300000
mu.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
mu.mem_map(stack, 65536, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(buffer, 8192, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(table, 4096, UC_PROT_READ | UC_PROT_WRITE)
# Put the input at the end of a mapped page, so an overread faults immediately.
pointer = buffer + 8192 - len(values)
if values:
    mu.mem_write(pointer, bytes(values))
mu.mem_write(table, struct.pack("<256I", *table_values))
mu.mem_protect(buffer, 8192, UC_PROT_READ)
mu.mem_protect(table, 4096, UC_PROT_READ)
trace = {"inputReads": 0, "tableReads": 0, "tableIndices": [], "emptyBranch": 0, "loopBranch": 0}
indices = set()
def memory(engine, access, address, size, value, context):
    if pointer <= address < pointer + len(values):
        if size != 1:
            raise ValueError("Unexpected input read width")
        trace["inputReads"] += 1
    elif table <= address < table + 1024:
        if size != 4 or (address - table) % 4:
            raise ValueError("Unexpected table read width")
        trace["tableReads"] += 1
        indices.add((address - table) // 4)
    elif not stack <= address < stack + 65536:
        raise ValueError("Unexpected original data read")
def code(engine, address, size, context):
    if address == int(manifest["entry"], 0) + 0x28:
        trace["emptyBranch"] += 1
    if address == int(manifest["entry"], 0) + 0x10:
        trace["loopBranch"] += 1
mu.hook_add(UC_HOOK_MEM_READ, memory)
mu.hook_add(UC_HOOK_CODE, code)
sp = stack + 65536 - 0x108
mu.mem_write(sp, struct.pack("<Q", stop))
mu.reg_write(UC_X86_REG_RSP, sp)
mu.reg_write(UC_X86_REG_RCX, state)
mu.reg_write(UC_X86_REG_RDX, pointer)
mu.reg_write(UC_X86_REG_R8, len(values))
mu.reg_write(UC_X86_REG_R9, table)
mu.emu_start(int(manifest["entry"], 0), stop, timeout=1000000, count=60000)
if mu.reg_read(UC_X86_REG_RIP) != stop:
    raise RuntimeError("Original did not return within limits")
if trace["inputReads"] != len(values) or trace["tableReads"] != len(values):
    raise ValueError("Original memory accesses differ from declared byte/table boundary")
if trace["emptyBranch"] != int(not values) or trace["loopBranch"] != len(values):
    raise ValueError("Original loop/empty branch differs from reviewed body")
trace["tableIndices"] = sorted(indices)
value = mu.reg_read(UC_X86_REG_EAX)
print(json.dumps({"value": value, "trace": trace} if "--trace" in sys.argv[1:] else value))
