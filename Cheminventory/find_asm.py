from capstone import *

with open("vmlinux", "rb") as f:
    code = f.read()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.skipdata = True  # skip bad bytes

last_instr = ""
for i in md.disasm(code, 0xffffffff81000000):
    if last_instr == "ret" and i.mnemonic == "or" and i.op_str.startswith("byte ptr [rax-0x7b]"):
        print(f"Found match at 0x{i.address - 1:x}")
    last_instr = i.mnemonic
