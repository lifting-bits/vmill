# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

python import re

b vmill_break_on_fault

set $__num_x86_trace_entries = 4096
set $__x86_trace_entry_size = 9 * 8
set $__imported_capstone = 0

define import-capstone
  if !$__imported_capstone
    set $__imported_capstone = 1
    python None ; \
      import capstone ; \
      x86_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32) ; \
      amd64_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64) ;
  end
  dont-repeat
end

define get-x86-trace-entry
  set $__n = $arg0 + 1
  set $__i = *((unsigned long *) &__vmill_x86_reg_trace_entry)
  set $__i = ($__i + $__num_x86_trace_entries - $__n) % $__num_x86_trace_entries
  set $__t = ((unsigned char *) &__vmill_x86_reg_trace_table)
  set $trace_entry = (unsigned long *) &($__t[$__i * $__x86_trace_entry_size])
  dont-repeat
end

# Print the N most recently executed instructions.
define print-x86-trace-instructions
  import-capstone

  set $memory = ('vmill::AddressSpace' *) $arg0
  set $__k = $arg1

  while $__k >= 0
    get-x86-trace-entry $__k
    set $__ea = *$trace_entry
    set $__va = $memory->ToReadOnlyVirtualAddress($__ea)

    set $__reg_eip = $trace_entry[0]
    set $__reg_eax = $trace_entry[1]
    set $__reg_ebx = $trace_entry[2]
    set $__reg_ecx = $trace_entry[3]
    set $__reg_edx = $trace_entry[4]
    set $__reg_esi = $trace_entry[5]
    set $__reg_edi = $trace_entry[6]
    set $__reg_ebp = $trace_entry[7]
    set $__reg_esp = $trace_entry[8]

    printf "%4d %p: ", $__k, $__va
    python None ; \
      reg_names = set("eip,eax,ebx,ecx,edx,esi,edi,ebp,esp".split(",")) ; \
      inst_ea = int(gdb.parse_and_eval("$__ea")) ; \
      inst_va = int(gdb.parse_and_eval("$__va")) ; \
      inst_bytes = gdb.selected_inferior().read_memory(inst_va, 15) ; \
      inst = next(x86_md.disasm(bytes(inst_bytes), inst_ea)) ; \
      gdb.write("{:>10}  {:<40}eip={:08x}".format( \
          inst.mnemonic, inst.op_str, inst_ea)) ; \
      parts = re.sub(r"[^a-z ]+", " ", inst.op_str) ; \
      used_regs = list(set(parts.split(" ")) & reg_names) ; \
      vals = ["  {}={:08x}".format(r, int(gdb.parse_and_eval("$__reg_{}".format(r)))) for r in used_regs] ; \
      gdb.write("{}\n".format("".join(vals)))

    set $__k = $__k - 1
  end
  dont-repeat
end

# Print the N most recently executed instructions.
define print-amd64-trace-instructions
  import-capstone

  set $memory = ('vmill::AddressSpace' *) $arg0
  set $__k = $arg1

  while $__k >= 0
    get-x86-trace-entry $__k
    set $__ea = *$trace_entry
    set $__va = $memory->ToReadOnlyVirtualAddress($__ea)

    set $__reg_eip = (unsigned) $trace_entry[0]
    set $__reg_eax = (unsigned) $trace_entry[1]
    set $__reg_ebx = (unsigned) $trace_entry[2]
    set $__reg_ecx = (unsigned) $trace_entry[3]
    set $__reg_edx = (unsigned) $trace_entry[4]
    set $__reg_esi = (unsigned) $trace_entry[5]
    set $__reg_edi = (unsigned) $trace_entry[6]
    set $__reg_ebp = (unsigned) $trace_entry[7]
    set $__reg_esp = (unsigned) $trace_entry[8]

    set $__reg_rip = $trace_entry[0]
    set $__reg_rax = $trace_entry[1]
    set $__reg_rbx = $trace_entry[2]
    set $__reg_rcx = $trace_entry[3]
    set $__reg_rdx = $trace_entry[4]
    set $__reg_rsi = $trace_entry[5]
    set $__reg_rdi = $trace_entry[6]
    set $__reg_rbp = $trace_entry[7]
    set $__reg_rsp = $trace_entry[8]

    printf "%4d %p: ", $__k, $__va
    python None ; \
      reg_names = set("eip,eax,ebx,ecx,edx,esi,edi,ebp,esp,rip,rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp".split(",")) ; \
      inst_ea = int(gdb.parse_and_eval("$__ea")) ; \
      inst_va = int(gdb.parse_and_eval("$__va")) ; \
      inst_bytes = gdb.selected_inferior().read_memory(inst_va, 15) ; \
      inst = next(amd64_md.disasm(bytes(inst_bytes), inst_ea)) ; \
      gdb.write("{:>10}  {:<40}rip={:08x}".format( \
          inst.mnemonic, inst.op_str, inst_ea)) ; \
      parts = re.sub(r"[^a-z ]+", " ", inst.op_str) ; \
      used_regs = list(set(parts.split(" ")) & reg_names) ; \
      vals = ["  {}={:08x}".format(r, int(gdb.parse_and_eval("$__reg_{}".format(r)))) for r in used_regs] ; \
      gdb.write("{}\n".format("".join(vals)))

    set $__k = $__k - 1
  end
  dont-repeat
end

# Print the Nth most recently recorded register trace entry.
define print-x86-trace-entry
  get-x86-trace-entry $arg0
  set $__e = $trace_entry
  printf "  eip = %08x at %p\n", $__e[0], &($__e[0])
  printf "  eax = %08x at %p\n", $__e[1], &($__e[1])
  printf "  ebx = %08x at %p\n", $__e[2], &($__e[2])
  printf "  ecx = %08x at %p\n", $__e[3], &($__e[3])
  printf "  edx = %08x at %p\n", $__e[4], &($__e[4])
  printf "  esi = %08x at %p\n", $__e[5], &($__e[5])
  printf "  edi = %08x at %p\n", $__e[6], &($__e[6])
  printf "  ebp = %08x at %p\n", $__e[7], &($__e[7])
  printf "  esp = %08x at %p\n", $__e[8], &($__e[8])
  dont-repeat
end

# Print the Nth most recently recorded register trace entry.
define print-amd64-trace-entry
  get-x86-trace-entry $arg0
  set $__e = $trace_entry
  printf "  rip = %016lx at %p\n", $__e[0], &($__e[0])
  printf "  rax = %016lx at %p\n", $__e[1], &($__e[1])
  printf "  rbx = %016lx at %p\n", $__e[2], &($__e[2])
  printf "  rcx = %016lx at %p\n", $__e[3], &($__e[3])
  printf "  rdx = %016lx at %p\n", $__e[4], &($__e[4])
  printf "  rsi = %016lx at %p\n", $__e[5], &($__e[5])
  printf "  rdi = %016lx at %p\n", $__e[6], &($__e[6])
  printf "  rbp = %016lx at %p\n", $__e[7], &($__e[7])
  printf "  rsp = %016lx at %p\n", $__e[8], &($__e[8])
  dont-repeat
end
