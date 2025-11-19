import idaapi
import idc
import idautils
import ida_bytes
import ida_auto
import time

pattern = [
    {"inst": idaapi.NN_mov, "op1": idaapi.o_reg, "op2": idaapi.o_mem},
    {"inst": idaapi.NN_mov, "op1": idaapi.o_reg, "op2": idaapi.o_imm},
    {"inst": idaapi.NN_sub, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_callni, "op1": idaapi.o_reg, "op2": idaapi.o_void},
]


def get_text_section_bounds():
        # Get .text section bounds
    text_seg = None
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg and idc.get_segm_name(seg_ea) == ".text":
            return (seg.start_ea, seg.end_ea)    
    return (None,None)

    


def pack_mov_rax_imm64(value):
    v = value & 0xFFFFFFFFFFFFFFFF
    return b"\x48\xb8" + v.to_bytes(8, "little")

def find_instruction_pattern(pattern):
    """
    Find the pattern: mov reg, [mem] -> mov reg, imm -> add reg, reg -> call reg
    """
    print("[*] Starting pattern search in .text section...")
    
    start_ea, end_ea = get_text_section_bounds()
    if start_ea is None or end_ea is None:
        print("[!] .text section not found!")
        return
    
    print(f"[*] .text section: 0x{start_ea:X} - 0x{end_ea:X}")
    
    matches = []
    ea = start_ea
    while ea < end_ea:
        # Check if we have enough space for 4 instructions
        if ea + 16 > end_ea:  # Conservative estimate
            break
        # print(f"[*] Checking: 0x{ea:08X}")
        # Get first instruction
        inst = idautils.DecodeInstruction(ea)
        if not inst:
            print(f"[!] <0x{ea:08X}> Instruction decoding failed!")
            ea = idc.next_head(ea+1)
            continue

        is_match=True
        instn = inst
        size=0
        for i, pat in enumerate(pattern):
            if instn.itype != pat['inst'] or instn.Op1.type != pat['op1'] or instn.Op2.type != pat['op2']:
                is_match=False
                break
            if instn.itype not in [idaapi.NN_callni, idaapi.NN_sub, idaapi.NN_lea] or (instn.itype == idaapi.NN_sub and instn.Op1.type == idaapi.o_reg and instn.Op2.type == idaapi.o_reg):
                # print(f"Adding size {instn.itype} ({instn.size})")
                size+=instn.size
            instn = idautils.DecodeInstruction(instn.ea + instn.size)
            # print(f"[*] <{ea:08X}> Instructioin match {i}")

        if not is_match:
            ea = idc.next_head(ea)
            continue

        # total_size = (instn.ea-ea)-instn.size
        # Found complete pattern
        match = {
            'address': ea,
            'total_size': size,
        }
        matches.append(match)
        print(f"[+] Pattern found at 0x{ea:X}")
        ea = idc.next_head(ea)

    
    # Print results
    print(f"\n[*] Found {len(matches)} pattern matches:")
    print("=" * 80)
    
    return matches

def fix_bytes(matches):
    """
    Analyze the context around found patterns for additional insights
    """
    if not matches:
        return
        
    print(f"\n[*] Analyzing context for {len(matches)} matches...")
    print("=" * 80)
    patch_count=0

    start_ea, end_ea = get_text_section_bounds()
    if start_ea is None or end_ea is None:
        print("[!] .text section not found!")
        return
    
    for i, match in enumerate(matches):
        ea = match['address']
        total_orig_len = match['total_size']
        mem_addr = idc.get_operand_value(ea, 1)
        # get qword at that mem_addr
        try:
            mem_val = ida_bytes.get_qword(mem_addr)
        except Exception:
            # fallback to idc.get_qword
            mem_val = idc.get_qword(mem_addr)
        ea1 = idc.next_head(ea)
        if ea1 == idc.BADADDR:
            ea = idc.next_head(ea+1)
            continue
        imm_val = idc.get_operand_value(ea1, 1)
        new_value = abs(mem_val - imm_val) & ((1<<64)-1)
        if new_value > end_ea or new_value < start_ea:
            print(f"[!] <0x{ea:08X}> Deobfuscation failed. Skippnig...")
            continue            
        assembled = pack_mov_rax_imm64(new_value)
        if assembled is None:
            print(f"[!] <0x{ea:08X}> Assembling failed. Aborting this match.")
            continue
       # write assembled bytes at ea
        ida_bytes.patch_bytes(ea, assembled)
        written = len(assembled)
        # pad remaining bytes with NOPs
        pad_len = total_orig_len - written
        if pad_len < 0:
            # new instruction longer than original total -- do not patch
            print("New instruction ({} bytes) is larger than original total ({} bytes). Skipping patch to avoid clobber.".format(written, total_orig_len))
        else:
            for i in range(pad_len):
                ida_bytes.patch_byte(ea + written + i, 0x90)  # NOP
            # recreate instruction(s)
            cur = ea
            end = ea + total_orig_len
            while cur < end:
                idc.create_insn(cur)
                cur = idc.next_head(cur)
            print("Patched 0x{:X}..0x{:X} (0x{:X}), padded {} bytes".format(ea, ea+total_orig_len, new_value, pad_len))
            # (OPTIONAL) add comment about original values
            comment = "original: [0x{:X}] + 0x{:X} -> 0x{:X}".format(mem_val, imm_val, new_value)
            patch_count+=1
            idc.set_cmt(ea, comment, total_orig_len)
    print(f"[+] Total patch count: {patch_count}")
    print("[+] All done!")


def main():
    """
    Main function to run the pattern finder
    """
    print("[*] IDA Pattern Finder - Searching for: mov-mov-add-call obfuscation")
    print("=" * 90)
    
    # Find the pattern
    matches = find_instruction_pattern(pattern)
    print(f"[+] Found {len(matches)} patterns.")
    if matches:
        # Analyze context if patterns were found
        print("[*] Pathcing bytes...")
        fix_bytes(matches)
    else:
        print("[!] No patterns found in .text section for pattern 1")

if __name__ == "__main__":
    main()