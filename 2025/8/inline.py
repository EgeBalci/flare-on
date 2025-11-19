import idaapi
import idc
import idautils
import ida_funcs
import ida_bytes




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

def find_instruction_pattern(addr):
    func = ida_funcs.get_func(addr)
    if not func:
        print(f"[!] No function foun at address {addr:8X}")
    start_ea = func.start_ea
    end_ea = func.end_ea

    print(f"[*] SEARCHING SEQUENCE (0x{start_ea:08X} - 0x{end_ea:08X})")
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
        # print(f"Checking -> 0x{inst.ea:08X}")

        ctx = {}
        if inst.itype == idaapi.NN_mov and inst.Op1.type == idaapi.o_reg and inst.Op2.type == idaapi.o_imm:
            rax = idc.get_operand_value(inst.ea, 1)
            ctx['mov']= {'ea': inst.ea, 'rax': rax, 'size': inst.size}
            
            inst = idautils.DecodeInstruction(inst.ea + inst.size)
            nop_space=0
            while inst.itype == idaapi.NN_nop:
                nop_space+=1
                inst = idautils.DecodeInstruction(inst.ea + inst.size)
            
            ctx['nop_space'] = nop_space
            if nop_space == 0:
                ea = idc.next_head(ea+inst.size)
                continue

            print(f"[*] <0x{inst.ea:08X}> MOV RAX, {rax:08X}")
            print(f"[*] <0x{inst.ea:08X}> NOP Space: {nop_space}")
            if inst.itype == idaapi.NN_lea:
                print(f"[*] <0x{inst.ea:08X}> LEA")
                ctx['lea'] = {'ea': inst.ea, 'size':inst.size}
                inst = idautils.DecodeInstruction(inst.ea + inst.size)

            if inst.itype == idaapi.NN_mov and inst.Op1.type == idaapi.o_displ:
                print(f"[*] <0x{inst.ea:08X}> MOV2")
                ctx['mov2'] = {'ea': inst.ea, 'size':inst.size}
                inst = idautils.DecodeInstruction(inst.ea + inst.size)

                
            if inst.itype != idaapi.NN_callni:
                print(f"[!] <0x{inst.ea:08X}> Unexpected instruction!")
                ea = idc.next_head(ea+inst.size)
                continue

            print(f"[*] <0x{inst.ea:08X}> CALL RAX")
            ctx['call'] = inst.ea

            matches.append(ctx)
            print(f"[+] Found sequence match: 0x{ea:08X}")

        ea = idc.next_head(ea)

    
    # Print results
    print(f"\n[*] Found {len(matches)} pattern matches:")
    print("=" * 80)
    
    return matches

def inline_funcs(matches):
    if not matches:
        return
        
    print(f"\n[*] Analyzing context for {len(matches)} matches...")
    print("=" * 80)
    patch_count=0
    
    for i, match in enumerate(matches):
        mov_ea = match['mov']['ea']
        mov_size = match['mov']['size']
        rax = match['mov']['rax']
        call_ea = match['call']
        nop_space = match['nop_space']

        print(f"[*] <0x{call_ea:08X}> Inlining call...")

        func = ida_funcs.get_func(rax)
        if not func:
            print(f"[-] Function not found at address 0x{rax:08X}")
            continue

        fbody = ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea -1 )# discard the ret
        print(f"[*] <0x{call_ea:08X}> Function size: {len(fbody)}")
        if len(fbody) > nop_space+2:
            print(f"[!] Function size is larger than NOP space. Aborting...")
            continue

        for i in range(mov_size):
            ida_bytes.patch_byte(mov_ea+i, 0x90)

        ida_bytes.patch_byte(call_ea, 0x90)
        ida_bytes.patch_byte(call_ea+1, 0x90)

        if 'lea' in match: 
            lea_ea = match['lea']['ea']
            lea_size = match['lea']['size']
            lea_bytes = ida_bytes.get_bytes(lea_ea, lea_size)
            ida_bytes.patch_bytes(mov_ea, lea_bytes)
            for i in range(lea_size):
                ida_bytes.patch_byte(lea_ea+i, 0x90)
            if 'mov2' in match:
                mov2_ea = match['mov2']['ea']
                mov2_size = match['mov2']['size']
                mov2_bytes = ida_bytes.get_bytes(mov2_ea, mov2_size)
                ida_bytes.patch_bytes(mov_ea+lea_size, lea_bytes)
                for i in range(mov2_size):
                    ida_bytes.patch_byte(mov_ea+i, 0x90)
                ida_bytes.patch_bytes(mov_ea+lea_size+mov2_size, fbody)
            else:
                ida_bytes.patch_bytes(mov_ea+lea_size, fbody)
        else:
            ida_bytes.patch_bytes(mov_ea, fbody)
        
        print(f"[+] <0x{call_ea:08X}> Inlined!")
    print("[+] All done!")


def main():
    """
    Main function to run the pattern finder
    """
    print("[*] IDA Pattern Finder - Searching for: mov-mov-add-call obfuscation")
    print("=" * 90)
    
    # Find the pattern
    matches = find_instruction_pattern(0x0000000140081760)
    print(f"[+] Found {len(matches)} patterns.")
    if matches:
        # Analyze context if patterns were found
        print("[*] Patching bytes...")
        inline_funcs(matches)
        
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