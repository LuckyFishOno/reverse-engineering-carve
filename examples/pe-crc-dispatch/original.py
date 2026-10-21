"""Original CRC initializer and indirect dispatch with an explicit CPU predicate stub."""
import hashlib
import json
from pathlib import Path
import struct
import sys
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RIP, UC_X86_REG_RAX, UC_X86_REG_EAX
root = Path(__file__).resolve().parent
payload = sys.stdin.buffer.read(32769)
if len(payload) > 32768:
    raise ValueError("Input budget exceeded")
args = json.loads(payload)
if not isinstance(args, list) or len(args) != 4:
    raise ValueError("CPU predicate, state, bytes and alignment required")
profile, state, values, alignment = args
if type(profile) is not int or profile not in [0, 1] or type(alignment) is not int or not 0 <= alignment <= 7:
    raise ValueError("CPU predicate0or1and alignment0to7required")
if type(state) is not int or not 0 <= state <= 0xffffffff or not isinstance(values, list) or len(values) > 4096 or any(type(v) is not int or not 0 <= v <= 255 for v in values):
    raise ValueError("uint32state and bounded bytes required")
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
stop, stack, buffer = 0x70000000, 0x70100000, 0x70200000
mu.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
mu.mem_map(stack, 65536, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(buffer, 12288, UC_PROT_READ | UC_PROT_WRITE)
pointer = buffer + 4096 + alignment
if values:
    mu.mem_write(pointer, bytes(values))
mu.mem_protect(buffer, 12288, UC_PROT_READ)
table = 0x6a5c6ba0
slots = {0x6a5c6b88, 0x6a5c8ba0, 0x6a5c6b80}
phase = "initialize"
trace = {"tableWrites": 0, "pointerWrites": [], "cpuPredicateCalls": 0, "selectedEntryHits": 0, "inputReads": 0, "tableReads": 0}
if any(mu.mem_read(table, 8192)) or any(struct.unpack("<Q", mu.mem_read(slot, 8))[0] for slot in slots):
    raise ValueError("Expected uninitialized original BSS")
def write(engine, access, address, size, value, context):
    if stack <= address and address + size <= stack + 65536:
        return
    if phase == "initialize" and table <= address and address + size <= table + 8192 and size == 4:
        trace["tableWrites"] += 1
        return
    if phase == "initialize" and address in slots and size == 8:
        trace["pointerWrites"].append({"address": hex(address), "value": hex(value)})
        return
    raise ValueError("Unexpected original global write")
def read(engine, access, address, size, value, context):
    if phase != "compute" or stack <= address and address + size <= stack + 65536:
        return
    if pointer <= address and address + size <= pointer + len(values):
        trace["inputReads"] += 1
        return
    if table <= address and address + size <= table + 8192 and size == 4:
        trace["tableReads"] += 1
        return
    if address == 0x6a5c6b88 and size == 8:
        return
    raise ValueError("Unexpected original computation read")
def code(engine, address, size, context):
    if phase == "initialize" and address == 0x6a41e6a0:
        trace["cpuPredicateCalls"] += 1
        sp = engine.reg_read(UC_X86_REG_RSP)
        engine.reg_write(UC_X86_REG_RAX, profile)
        engine.reg_write(UC_X86_REG_RSP, sp + 8)
        engine.reg_write(UC_X86_REG_RIP, struct.unpack("<Q", engine.mem_read(sp, 8))[0])
    if phase == "compute" and address in [0x6a42c5c0, 0x6a42c680]:
        if address != selected:
            raise ValueError("Entered unselected CRC implementation")
        trace["selectedEntryHits"] += 1
mu.hook_add(UC_HOOK_MEM_WRITE, write)
mu.hook_add(UC_HOOK_MEM_READ, read)
mu.hook_add(UC_HOOK_CODE, code)
def execute(entry):
    sp = stack + 65536 - 0x108
    mu.mem_write(sp, struct.pack("<Q", stop))
    mu.reg_write(UC_X86_REG_RSP, sp)
    mu.emu_start(entry, stop, timeout=1000000, count=200000)
    if mu.reg_read(UC_X86_REG_RIP) != stop:
        raise RuntimeError("Original did not return within limits")
if "--skip-init" not in sys.argv:
    execute(0x6a42c510)
selected = struct.unpack("<Q", mu.mem_read(0x6a5c6b88, 8))[0]
if selected != (0x6a42c5c0 if profile else 0x6a42c680):
    raise ValueError("Original CRC dispatch pointer not initialized as declared")
if trace["tableWrites"] != 2048 or trace["cpuPredicateCalls"] != 1:
    raise ValueError("Original initializer did not produce2048table cells and one CPU predicate call")
initialized_table = bytes(mu.mem_read(table, 8192))
# Original table/pointers become immutable during the selected computation.
mu.mem_protect(base, (m["sizeOfImage"] + 4095) & ~4095, UC_PROT_READ)
for section in m["sections"]:
    if section["characteristics"] & 0x20000000:
        length = (max(section["rawSize"], section["virtualSize"]) + 4095) & ~4095
        mu.mem_protect(base + section["virtualAddress"], length, UC_PROT_READ | UC_PROT_EXEC)
phase = "compute"
mu.reg_write(UC_X86_REG_RCX, state)
mu.reg_write(UC_X86_REG_RDX, pointer)
mu.reg_write(UC_X86_REG_R8, len(values))
execute(0x6a42c4a0)
if trace["selectedEntryHits"] != 1 or bool(trace["inputReads"]) != bool(values) or bool(trace["tableReads"]) != bool(values):
    raise ValueError("Missing original dispatch or input/table access")
result = {"value": mu.reg_read(UC_X86_REG_EAX), "implementation": "T4" if profile else "T8"}
trace["selectedAddress"] = hex(selected)
trace["tableSha256"] = hashlib.sha256(initialized_table).hexdigest()
trace["table"] = list(struct.unpack("<2048I", initialized_table))
print(json.dumps({"result": result, "trace": trace} if "--trace" in sys.argv[1:] else result))
