import idaapi
import idc
import idautils


pattern = [
    {"inst": idaapi.NN_mov, "op1": idaapi.o_reg, "op2": idaapi.o_mem},
    {"inst": idaapi.NN_mov, "op1": idaapi.o_reg, "op2": idaapi.o_imm},
    {"inst": idaapi.NN_mov, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_or, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_mov, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_sub, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_and, "op1": idaapi.o_reg, "op2": idaapi.o_reg},    
    {"inst": idaapi.NN_mov, "op1": idaapi.o_reg, "op2": idaapi.o_imm},
    {"inst": idaapi.NN_lea, "op1": idaapi.o_reg, "op2": idaapi.o_phrase},
    {"inst": idaapi.NN_sub, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_mov, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_or, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_and, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_add, "op1": idaapi.o_reg, "op2": idaapi.o_reg},
    {"inst": idaapi.NN_jmpni, "op1": idaapi.o_reg, "op2": idaapi.o_void},
]


# fillers =[
#     idaapi.NN_mov,
#     idaapi.NN_and,
#     idaapi.NN_or,
#     idaapi.NN_sub,
#     idaapi.NN_add,
#     idaapi.NN_lea,
#     # idaapi.NN_neg,
# ]


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

def find_instruction_pattern():
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
        count=0
        for i, pat in enumerate(pattern):
            if instn.itype != pat['inst'] or instn.Op1.type != pat['op1'] or instn.Op2.type != pat['op2']:
                is_match=False
                break
            instn = idautils.DecodeInstruction(instn.ea + instn.size)
            count=i
            print(f"[*] 0x<{ea:08X}> Instructioin match {i}")

        if not is_match:
            ea = idc.next_head(ea+instn.size)
            continue


        # if instn.itype != idaapi.NN_jmp and instn.Op1.type != idaapi.o_reg:
        #     ea = idc.next_head(ea+instn.size)
        #     continue

        print(f"[+] Found sequence match: 0x{ea:08X}")

        # Calculate total size of the sequence
        total_size = (instn.ea-ea)+instn.size
        # Found complete pattern
        match = {
            'address': ea,
            'total_size': total_size,
        }
        matches.append(match)
        ea = idc.next_head(ea+instn.size)

    
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
    for i, match in enumerate(matches):
        ea = match['address']
        total_orig_len = match['total_size']
        print(f"[*] <0x{ea:08X}> Patching {total_orig_len} bytes... ")
        patch_count+=1
        # (OPTIONAL) add comment about original values
        idc.set_cmt(ea, "Removed obfuscated jmp", total_orig_len)
        for i in range(total_orig_len):
            ida_bytes.patch_byte(ea + i, 0x90)  # NOP

    print(f"[+] Total patch count: {patch_count}")
    print("[+] All done!")


def main():
    """
    Main function to run the pattern finder
    """
    print("[*] IDA Pattern Finder - Searching for: mov-mov-add-call obfuscation")
    print("=" * 90)
    
    # Find the pattern
    matches = find_instruction_pattern()
    print(f"[+] Found {len(matches)} patterns.")
    if matches:
        # Analyze context if patterns were found
        print("[*] Patching bytes...")
        fix_bytes(matches)
        
        # Ask user if they want to add comments
        # choice = idc.ask_yn(1, "Add comments to found patterns?")
        # if choice == 1:
        #     for match in matches:
        #         ea = match['address']
        #         comment = f"PATTERN: mov-mov-add-call obfuscated call sequence"
        #         idc.set_cmt(ea, comment, 0)
        #         print(f"[+] Added comment at 0x{ea:X}")
    else:
        print("[!] No patterns found in .text section")

if __name__ == "__main__":
    main()