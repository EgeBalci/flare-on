# IDAPython script: Inline calls made after long NOP sequences.
# Pattern:
#   mov     rax, IMM64             ; callee address -> RAX
#   nop
#   nop
#   ...
#   [optional] lea rcx, [ ... ]    ; argument setup
#   call    rax
#
# Action:
#   - Read IMM64 callee address
#   - NOP-out mov/lea/call
#   - Copy the (optional) LEA + callee body (up to but not including the terminal RET)
#     into the NOP sled
#   - Append a JMP to the instruction after the original CALL
#
# Tested on IDA 7.x (Python 3). May require minor adjustments for your IDA build.

import idaapi
import idc
import idautils
import ida_bytes
import ida_funcs

DRY_RUN = True  # Set to False to actually patch bytes

def mnem(ea):
    return idaapi.print_insn_mnem(ea) or ""

def opstr(ea, n):
    return idc.print_operand(ea, n) or ""

def optype(ea, n):
    return idc.get_operand_type(ea, n)

def insn_size(ea):
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea):
        return insn.size
    # fallback: assume 1 byte (NOP etc.) if decode fails
    return 1

def is_mov_rax_imm(ea):
    if mnem(ea).lower() != "mov":
        return False
    return opstr(ea, 0).lower() == "rax" and optype(ea, 1) == idc.o_imm

def is_nop(ea):
    return mnem(ea).lower() == "nop"

def is_lea_rcx(ea):
    return mnem(ea).lower() == "lea" and opstr(ea, 0).lower() == "rcx"

def is_call_rax(ea):
    return mnem(ea).lower() == "call" and opstr(ea, 0).lower() == "rax"

def get_bytes(ea, size):
    b = ida_bytes.get_bytes(ea, size)
    return b if b is not None else b""

def nop_out(ea, size):
    if DRY_RUN:
        return True
    try:
        ida_bytes.patch_bytes(ea, b"\x90" * size)
        return True
    except Exception as e:
        print(f"[!] Failed to NOP at {ea:016X}: {e}")
        return False

def write_bytes(ea, b):
    if DRY_RUN:
        return True
    try:
        ida_bytes.patch_bytes(ea, b)
        return True
    except Exception as e:
        print(f"[!] Failed to write {len(b)} bytes at {ea:016X}: {e}")
        return False

def try_assemble(ea, asm_line):
    """
    Assemble one instruction at 'ea' and return (ok, size).
    Uses idc.assemble for portability.
    """
    before = insn_size(ea)  # not reliable; we’ll re-decode after assemble
    if DRY_RUN:
        # We don't assemble in dry-run; predict max 5 bytes for near jmp.
        # We'll still do a quick feasibility check by assuming 5.
        return True, 5
    ok = idc.assemble(ea, asm_line)
    if not ok:
        return False, 0
    sz = insn_size(ea)
    return True, sz if sz > 0 else 1

def find_reachable_until_ret(start_ea, max_bytes=0x1000):
    """
    Collect linear bytes from start_ea up to but not including the first 'ret' instruction.
    Stops at function end if function info is available, otherwise stops after max_bytes.
    Returns (body_bytes, end_ea, ret_ea)
      - body_bytes: bytes [start_ea, ret_ea) (RET not included)
      - end_ea: address where we stopped scanning (normally ret_ea)
      - ret_ea: address of the 'ret' (None if not found)
    """
    body = bytearray()
    ea = start_ea
    visited = 0

    f = ida_funcs.get_func(start_ea)
    func_end = f.end_ea if f else start_ea + max_bytes

    while ea < func_end and visited < max_bytes:
        if mnem(ea).lower().startswith("ret"):
            return bytes(body), ea, ea
        sz = insn_size(ea)
        if sz <= 0:
            break
        b = get_bytes(ea, sz)
        if not b:
            break
        body += b
        ea += sz
        visited += sz

    # No RET found
    return bytes(body), ea, None

def process_function(func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        return

    changed_sites = 0

    ea = func.start_ea
    while ea < func.end_ea:
        if not idaapi.is_code(idaapi.get_flags(ea)):
            ea = idc.next_head(ea, func.end_ea)
            continue

        # Look for: mov rax, imm
        if not is_mov_rax_imm(ea):
            ea = idc.next_head(ea, func.end_ea)
            continue

        mov_ea = ea
        callee = idc.get_operand_value(mov_ea, 1)
        mov_sz = insn_size(mov_ea)
        if callee == idc.BADADDR:
            ea = idc.next_head(ea, func.end_ea)
            continue

        # Collect NOP sled (must be >= 1)
        ptr = idc.next_head(mov_ea, func.end_ea)
        if ptr == idc.BADADDR:
            break

        if not is_nop(ptr):
            # Not our pattern
            ea = ptr
            continue

        nop_start = ptr
        while ptr != idc.BADADDR and ptr < func.end_ea and is_nop(ptr):
            ptr = idc.next_head(ptr, func.end_ea)

        nop_end = ptr  # first non-NOP after sled
        sled_len = nop_end - nop_start

        # Optional: lea rcx, [...]
        lea_ea = None
        lea_sz = 0
        if ptr != idc.BADADDR and is_lea_rcx(ptr):
            lea_ea = ptr
            lea_sz = insn_size(lea_ea)
            ptr = idc.next_head(ptr, func.end_ea)

        # Must have: call rax
        if ptr == idc.BADADDR or not is_call_rax(ptr):
            # Not our pattern
            ea = ptr if ptr != idc.BADADDR else nop_end
            continue

        call_ea = ptr
        call_sz = insn_size(call_ea)
        after_call = idc.next_head(call_ea, func.end_ea)

        # Get LEA bytes if present (we’ll move it into the sled)
        lea_bytes = b""
        if lea_ea is not None:
            lea_bytes = get_bytes(lea_ea, lea_sz)

        # Extract callee body up to (but not including) RET.
        body_bytes, stop_ea, ret_ea = find_reachable_until_ret(callee)
        if ret_ea is None:
            print(f"[i] Skipping site at {mov_ea:016X}: callee {callee:016X} has no RET (or too large).")
            ea = idc.next_head(call_ea, func.end_ea)
            continue

        # Space we need in sled: len(lea_bytes) + len(body_bytes) + size(jmp)
        # We'll assume up to 5 bytes for near JMP rel32.
        needed = len(lea_bytes) + len(body_bytes) + 5
        if needed > sled_len:
            print(f"[i] Skipping site at {mov_ea:016X}: need {needed} bytes, have {sled_len}.")
            ea = idc.next_head(call_ea, func.end_ea)
            continue

        print(f"[+] Candidate at {mov_ea:016X}: callee {callee:016X}, sled {sled_len} bytes, will inline {len(body_bytes)} bytes.")

        # --- Patch sequence ---
        if not DRY_RUN:
            idaapi.auto_wait()

        # 1) NOP-out mov / lea / call
        ok = True
        ok &= nop_out(mov_ea, mov_sz)
        if lea_ea is not None:
            ok &= nop_out(lea_ea, lea_sz)
        ok &= nop_out(call_ea, call_sz)

        if not ok:
            print(f"[!] Failed to NOP-out at site {mov_ea:016X}, skipping.")
            ea = idc.next_head(call_ea, func.end_ea)
            continue

        # 2) Write LEA (if any) + callee body into sled
        cursor = nop_start
        if lea_bytes:
            ok &= write_bytes(cursor, lea_bytes)
            cursor += len(lea_bytes)
        if not ok:
            print(f"[!] Failed writing LEA at {nop_start:016X}")
            ea = idc.next_head(call_ea, func.end_ea)
            continue

        if body_bytes:
            ok &= write_bytes(cursor, body_bytes)
            cursor += len(body_bytes)
        if not ok:
            print(f"[!] Failed writing callee body at {cursor:016X}")
            ea = idc.next_head(call_ea, func.end_ea)
            continue

        # 3) Append JMP to after_call to replace the callee's RET we omitted
        jmp_asm = f"jmp 0x{after_call:016X}"
        ok_asm, jmp_size = try_assemble(cursor, jmp_asm)
        if not ok_asm:
            print(f"[!] Failed to assemble JMP at {cursor:016X}: {jmp_asm}")
            ea = idc.next_head(call_ea, func.end_ea)
            continue
        cursor_after_jmp = cursor + jmp_size

        # If not dry run, we actually assembled it; otherwise we just reserve space and fill NOPs
        if not DRY_RUN:
            # idc.assemble already wrote the bytes; nothing else needed
            pass
        else:
            # Reserve the bytes with 0xCC in dry-run to visualize (or just skip writing)
            # We'll just do nothing in dry-run; we only report feasibility.
            pass

        # 4) Fill remaining sled with NOPs
        remaining = (nop_end - cursor_after_jmp)
        if remaining > 0 and not DRY_RUN:
            write_bytes(cursor_after_jmp, b"\x90" * remaining)

        if DRY_RUN:
            print(f"    (dry-run) Would NOP mov/lea/call; inline {len(lea_bytes)}+{len(body_bytes)} bytes; JMP {jmp_size} bytes; slack {remaining} bytes.")
        else:
            print(f"[✓] Inlined at {mov_ea:016X}. Used {len(lea_bytes)}+{len(body_bytes)}+{jmp_size} bytes, {remaining} bytes NOP.")

        changed_sites += 1
        ea = idc.next_head(call_ea, func.end_ea)

    if changed_sites:
        print(f"[=] Function {func_ea:016X}: inlined {changed_sites} site(s).")
    else:
        print(f"[-] Function {func_ea:016X}: no matching sites.")

def main():
    print("[*] Scanning for MOV RAX, imm -> NOP-sled -> [LEA RCX, ...] -> CALL RAX pattern...")
    for f_ea in idautils.Functions():
        process_function(f_ea)
    if DRY_RUN:
        print("[*] Dry run complete. Set DRY_RUN=False to apply patches.")
    else:
        idaapi.auto_wait()
        idaapi.auto_mark_range(idaapi.cvar.inf.min_ea, idaapi.cvar.inf.max_ea, idaapi.AU_FINAL)
        print("[*] Patching complete. You may need to re-analyze the affected ranges.")

if __name__ == "__main__":
    main()
