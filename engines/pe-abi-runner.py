"""Fixed bounded PE runner. Configuration is rebound by Carve before verification."""
import hashlib
import json
import struct
import sys
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_EAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_EFLAGS

if unicorn.__version__ != "2.1.4":
    raise ValueError("This task pins Unicorn2.1.4")
if len(sys.argv) != 3:
    raise ValueError("Pinned task path and SHA256 required")
with open(sys.argv[1], "rb") as task_file:
    raw = task_file.read(1048577)
if len(raw) > 1048576 or hashlib.sha256(raw).hexdigest() != sys.argv[2]:
    raise ValueError("PE task differs from its pin")
task = json.loads(raw)
stateful = task["policy"] in ("single-function-stateful-scalars@1", "reviewed-functions-stateful-scalars@1", "reviewed-functions-stateful-inputs@1", "reviewed-functions-stateful-outputs@1")
if task["schema"] != "carve/pe-abi-task@1" or task["policy"] not in ("single-function-readonly-inputs@1", "single-function-stateful-scalars@1", "reviewed-functions-stateful-scalars@1", "reviewed-functions-stateful-inputs@1", "reviewed-functions-stateful-outputs@1", "single-function-output-buffers@1"):
    raise ValueError("Unsupported PE task policy")
payload = sys.stdin.buffer.read(65537)
if len(payload) > 65536:
    raise ValueError("Input budget exceeded")
args = json.loads(payload)
if stateful and (not isinstance(args, list) or not 1 <= len(args) <= 64):
    raise ValueError("One to64 calls required")
with open(task["source"]["path"], "rb") as source_file:
    data = source_file.read(16 * 1048576 + 1)
if len(data) > 16 * 1048576 or hashlib.sha256(data).hexdigest() != task["source"]["sha256"]:
    raise ValueError("Original image differs from its pin")
m = task["source"]["metadata"]
mu = Uc(UC_ARCH_X86, UC_MODE_64)
base = int(m["imageBase"], 0)
mu.mem_map(base, (m["sizeOfImage"] + 4095) & ~4095)
mu.mem_write(base, data[:m["sizeOfHeaders"]])
for section in m["sections"]:
    mu.mem_write(base + section["virtualAddress"], data[section["rawOffset"]:section["rawOffset"] + section["rawSize"]])
mu.mem_protect(base, (m["sizeOfImage"] + 4095) & ~4095, UC_PROT_READ)
for section in m["sections"]:
    if section["characteristics"] & 0x20000000:
        length = (max(section["virtualSize"], section["rawSize"]) + 4095) & ~4095
        if length:
            mu.mem_protect(base + section["virtualAddress"], length, UC_PROT_READ | UC_PROT_EXEC)
stack, stop = 0x72000000, 0x73000000
mu.mem_map(stack, 65536, UC_PROT_READ | UC_PROT_WRITE)
mu.mem_map(stop, 4096, UC_PROT_READ | UC_PROT_EXEC)
registers = {"rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX, "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9}
memory = [(int(r["address"], 0), int(r["address"], 0) + r["length"], r["access"]) for r in task.get("memory", [])]
for first, last, permission in memory:
    if permission in ("read-write", "initialize-write"):
        mu.mem_protect(first & ~4095, ((last + 4095) & ~4095) - (first & ~4095), UC_PROT_READ | UC_PROT_WRITE)
boundary_calls = {b["observationId"]: 0 for b in task.get("boundaries", [])}
invocation = 0
def invoke(args, function=task, initializing=False):
    global invocation
    current = invocation
    invocation += 1
    if stateful and current >= 72:
        raise ValueError("Invocation budget exceeded")
    if not isinstance(args, list) or len(args) != function["inputCount"]:
        raise ValueError("Wrong task argument count")
    # Volatile register and flag state must not leak between ABI calls.
    mu.reg_write(UC_X86_REG_EFLAGS, 2)
    mu.reg_write(UC_X86_REG_R10, 0)
    mu.reg_write(UC_X86_REG_R11, 0)
    mu.reg_write(UC_X86_REG_EAX, 0)
    for register in registers.values():
        mu.reg_write(register, 0)
    regions, lengths, mapped, outputs = [], {}, [], []
    def uint32(value):
        return type(value) is int and 0 <= value <= 0xffffffff
    for index, binding in enumerate(function["bindings"]):
        if binding["kind"] == "length":
            continue
        value = args[binding["argument"]]
        if binding["kind"] == "uint32":
            if not uint32(value):
                raise ValueError("uint32 argument required")
        else:
            if binding["kind"] != "output-bytes" and not isinstance(value, list):
                raise ValueError("Array argument required")
            if binding["kind"] == "output-bytes":
                if not uint32(value) or value > binding["maxLength"]:
                    raise ValueError("Bounded output capacity required")
                encoded = bytes(value)
            elif binding["kind"] in ("bytes", "inout-bytes"):
                if len(value) > binding["maxLength"] or any(type(v) is not int or not 0 <= v <= 255 for v in value):
                    raise ValueError("Bounded byte array required")
                encoded = bytes(value)
            elif binding["kind"] == "uint32-array":
                if len(value) != binding["length"] or any(not uint32(v) for v in value):
                    raise ValueError("Fixed uint32 array required")
                encoded = struct.pack("<" + "I" * len(value), *value)
            else:
                raise ValueError("Unsupported buffer binding")
            region = 0x71000000 + (current * 0x10000 + index * 0x3000 if stateful else index * 0x20000)
            mu.mem_map(region, 8192, UC_PROT_READ | UC_PROT_WRITE)
            mapped.append(region)
            value = region + 8192 - len(encoded)
            if "alignment" in binding:
                value -= (value - binding["alignment"]) % 8
            if encoded:
                mu.mem_write(value, encoded)
            if binding["kind"] in ("output-bytes", "inout-bytes"):
                outputs.append({"parameter": binding["parameter"], "start": value, "end": value + len(encoded), "initialized": set(range(value, value + len(encoded))) if binding["kind"] == "inout-bytes" else set()})
            else:
                mu.mem_protect(region, 8192, UC_PROT_READ)
                regions.append((value, value + len(encoded)))
            lengths[binding["parameter"]] = len(encoded)
        mu.reg_write(registers[binding["register"]], value)
    for binding in function["bindings"]:
        if binding["kind"] == "length":
            mu.reg_write(registers[binding["register"]], lengths[binding["of"]])
    saved = [UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
    for index, register in enumerate(saved):
        mu.reg_write(register, 0x1122334400 + index)
    sp = stack + 65536 - 0x108
    mu.mem_write(sp, struct.pack("<Q", stop))
    mu.reg_write(UC_X86_REG_RSP, sp)
    written = set(range(sp, sp + 8))
    body = [(int(r["start"], 0), int(r["end"], 0) + 1) for r in function["body"] + [r for helper in task.get("helpers", []) for r in helper["body"]]]
    def read(engine, access, address, size, value, context):
        if any(o["start"] <= address and address + size <= o["end"] and all(p in o["initialized"] for p in range(address, address + size)) for o in outputs):
            return
        if any(start <= address and address + size <= end for start, end in regions) or any(first <= address and address + size <= last for first, last, permission in memory):
            return
        if stack <= address and address + size <= stack + 65536 and all(p in written for p in range(address, address + size)):
            return
        raise ValueError("Undeclared memory or uninitialized stack read at " + hex(address) + " size " + str(size))
    def write(engine, access, address, size, value, context):
        for output in outputs:
            if output["start"] <= address and address + size <= output["end"]:
                output["initialized"].update(range(address, address + size))
                return
        if any(first <= address and address + size <= last and (permission == "read-write" or initializing and permission == "initialize-write") for first, last, permission in memory):
            return
        if not stack <= address or address + size > stack + 65536:
            raise ValueError("Undeclared memory write at " + hex(address) + " size " + str(size))
        written.update(range(address, address + size))
    def code(engine, address, size, context):
        for boundary in task.get("boundaries", []):
            if address != int(boundary["entry"], 0):
                continue
            if not initializing:
                raise ValueError("Predicate boundary is restricted to initialization")
            key = boundary["observationId"]
            if boundary_calls[key] >= boundary["expectedCalls"]:
                raise ValueError("Predicate boundary call budget exceeded")
            current_sp = engine.reg_read(UC_X86_REG_RSP)
            if not stack <= current_sp or current_sp + 8 > stack + 65536 or not all(p in written for p in range(current_sp, current_sp + 8)):
                raise ValueError("Predicate boundary requires an initialized stack return")
            target = struct.unpack("<Q", engine.mem_read(current_sp, 8))[0]
            if not any(first <= target < last for first, last in body):
                raise ValueError("Predicate boundary must return into a reviewed caller body")
            boundary_calls[key] += 1
            engine.reg_write(UC_X86_REG_EAX, boundary["result"])
            engine.reg_write(UC_X86_REG_RSP, current_sp + 8)
            engine.reg_write(UC_X86_REG_RIP, target)
            return
        if not any(start <= address and address + size <= end for start, end in body):
            raise ValueError("Execution escaped the reviewed function body")
    hooks = [mu.hook_add(UC_HOOK_MEM_READ, read), mu.hook_add(UC_HOOK_MEM_WRITE, write), mu.hook_add(UC_HOOK_CODE, code)]
    try:
        mu.emu_start(int(function["entry"], 0), stop, timeout=task["spec"]["timeoutMicros"], count=task["spec"]["instructionLimit"])
        observed = {o["parameter"]: [int(mu.mem_read(p, 1)[0]) if p in o["initialized"] else None for p in range(o["start"], o["end"])] for o in outputs}
    finally:
        for hook in hooks:
            mu.hook_del(hook)
        for region in mapped:
            mu.mem_unmap(region, 8192)
    if mu.reg_read(UC_X86_REG_RIP) != stop or mu.reg_read(UC_X86_REG_RSP) != sp + 8:
        raise RuntimeError("Original failed to return within task limits or stack balance")
    if any(mu.reg_read(register) != 0x1122334400 + index for index, register in enumerate(saved)):
        raise ValueError("Original changed an integer nonvolatile register")
    result = mu.reg_read(UC_X86_REG_EAX)
    return {"returnValue": result, "outputs": observed} if outputs else result

if stateful:
    for initial in task["initializers"]:
        invoke(initial["args"], initial, initializing=True)
    if any(boundary_calls[b["observationId"]] != b["expectedCalls"] for b in task.get("boundaries", [])):
        raise ValueError("Required initialization predicate boundary call count not observed")
    for region in task.get("memory", []):
        if "initializedSha256" in region and hashlib.sha256(bytes(mu.mem_read(int(region["address"], 0), region["length"]))).hexdigest() != region["initializedSha256"]:
            raise ValueError("Initialized memory differs from its declared SHA256 at " + region["address"])
    print(json.dumps([{"kind": "return", "value": invoke(call)} for call in args]))
else:
    print(json.dumps(invoke(args)))
