import idaapi
import idc
import ida_bytes
import ida_ua
import ida_funcs
import ida_idp

def get_instruction_size(ea):
    """Get the size of an instruction at the given address."""
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) > 0:
        return insn.size
    return 0

def is_nop(ea):
    """Check if the instruction at ea is a NOP."""
    mnem = idc.print_insn_mnem(ea)
    return mnem and mnem.lower() == "nop"

def is_mov_rax_imm(ea):
    """Check if instruction is MOV RAX, immediate_value."""
    mnem = idc.print_insn_mnem(ea)
    if mnem and mnem.lower() == "mov":
        op0 = idc.print_operand(ea, 0)
        op1 = idc.print_operand(ea, 1)
        if op0 and op0.lower() == "rax":
            # Check if second operand is an immediate value (address)
            op_type = idc.get_operand_type(ea, 1)
            if op_type == idc.o_imm:
                return True, idc.get_operand_value(ea, 1)
    return False, None

def is_lea_rcx(ea):
    """Check if instruction is LEA RCX, [addr]."""
    mnem = idc.print_insn_mnem(ea)
    if mnem and mnem.lower() == "lea":
        op0 = idc.print_operand(ea, 0)
        if op0 and op0.lower() == "rcx":
            return True
    return False

def is_call_rax(ea):
    """Check if instruction is CALL RAX."""
    mnem = idc.print_insn_mnem(ea)
    if mnem and mnem.lower() == "call":
        op0 = idc.print_operand(ea, 0)
        if op0 and op0.lower() == "rax":
            return True
    return False

def find_pattern_sequences():
    """Find all sequences matching the pattern: MOV RAX, addr -> NOPs -> [LEA RCX] -> CALL RAX."""
    sequences = []
    
    # Search through all segments
    for seg_ea in idautils.Segments():
        seg_end = idc.get_segm_end(seg_ea)
        ea = seg_ea
        
        while ea < seg_end:
            # Check for MOV RAX, immediate
            is_mov, call_addr = is_mov_rax_imm(ea)
            if is_mov:
                mov_ea = ea
                mov_size = get_instruction_size(ea)
                ea += mov_size
                
                # Count NOPs
                nop_start = ea
                nop_count = 0
                while ea < seg_end and is_nop(ea):
                    nop_count += 1
                    ea += get_instruction_size(ea)
                
                if nop_count == 0:
                    continue
                
                # Check for optional LEA RCX
                lea_ea = None
                lea_size = 0
                if is_lea_rcx(ea):
                    lea_ea = ea
                    lea_size = get_instruction_size(ea)
                    ea += lea_size
                
                # Check for CALL RAX
                if is_call_rax(ea):
                    call_ea = ea
                    call_size = get_instruction_size(ea)
                    
                    sequence = {
                        'mov_ea': mov_ea,
                        'mov_size': mov_size,
                        'call_addr': call_addr,
                        'nop_start': nop_start,
                        'nop_count': nop_count,
                        'lea_ea': lea_ea,
                        'lea_size': lea_size,
                        'call_ea': call_ea,
                        'call_size': call_size,
                        'total_size': call_ea + call_size - mov_ea
                    }
                    sequences.append(sequence)
                    print(f"Found pattern at 0x{mov_ea:X}: MOV RAX, 0x{call_addr:X} -> {nop_count} NOPs -> {'LEA RCX -> ' if lea_ea else ''}CALL RAX")
                    ea += call_size
                else:
                    ea += 1
            else:
                ea += 1
    
    return sequences

def get_function_bytes(func_addr, max_size=None):
    """Get the bytes of a function starting at func_addr."""
    func = ida_funcs.get_func(func_addr)
    if func:
        func_size = func.end_ea - func.start_ea
        if max_size and func_size > max_size:
            func_size = max_size
        return ida_bytes.get_bytes(func_addr, func_size), func_size
    else:
        # If not a recognized function, try to get a reasonable amount of bytes
        # Look for RET instruction to determine function end
        ea = func_addr
        max_search = max_size if max_size else 0x1000  # Search up to 4KB
        for offset in range(max_search):
            mnem = idc.print_insn_mnem(ea + offset)
            if mnem and mnem.lower() in ["ret", "retn"]:
                func_size = offset + get_instruction_size(ea + offset)
                return ida_bytes.get_bytes(func_addr, func_size), func_size
        
        # If no RET found, use a default size
        default_size = min(0x100, max_size) if max_size else 0x100
        return ida_bytes.get_bytes(func_addr, default_size), default_size

def inline_function(sequence):
    """Inline the function call by replacing the sequence with the function body."""
    call_addr = sequence['call_addr']
    mov_ea = sequence['mov_ea']
    total_size = sequence['total_size']
    
    # Calculate available space (NOPs + MOV + LEA + CALL)
    available_space = total_size
    
    print(f"\nInlining function 0x{call_addr:X} at 0x{mov_ea:X}")
    print(f"Available space: {available_space} bytes")
    
    # Get the function bytes to inline
    func_bytes, func_size = get_function_bytes(call_addr, available_space)
    
    if func_size > available_space:
        print(f"Warning: Function size ({func_size}) exceeds available space ({available_space}). Truncating.")
        func_size = available_space
        func_bytes = func_bytes[:func_size]
    
    # Prepare the new bytes
    new_bytes = bytearray()
    
    # If there's a LEA RCX instruction, preserve it at the beginning
    if sequence['lea_ea']:
        lea_bytes = ida_bytes.get_bytes(sequence['lea_ea'], sequence['lea_size'])
        new_bytes.extend(lea_bytes)
        print(f"Preserving LEA RCX instruction ({sequence['lea_size']} bytes)")
    
    # Add the function body (minus any trailing RET if space is tight)
    func_to_add = func_bytes
    if len(new_bytes) + len(func_to_add) > available_space:
        # Remove trailing RET if necessary to fit
        for i in range(len(func_to_add) - 1, -1, -1):
            ea = call_addr + i
            mnem = idc.print_insn_mnem(ea)
            if mnem and mnem.lower() in ["ret", "retn"]:
                func_to_add = func_to_add[:i]
                print(f"Removed trailing RET to fit in available space")
                break
    
    new_bytes.extend(func_to_add)
    
    # Fill remaining space with NOPs
    remaining = available_space - len(new_bytes)
    if remaining > 0:
        new_bytes.extend([0x90] * remaining)  # 0x90 is NOP
        print(f"Added {remaining} NOPs to fill remaining space")
    
    # Patch the bytes
    ida_bytes.patch_bytes(mov_ea, bytes(new_bytes))
    print(f"Successfully inlined {len(func_to_add)} bytes of function code")
    
    # Refresh the view
    idaapi.auto_wait()
    
    return True

def main():
    """Main function to find and inline all matching sequences."""
    print("=" * 60)
    print("Function Inliner Script")
    print("=" * 60)
    
    # Find all matching sequences
    sequences = find_pattern_sequences()
    
    if not sequences:
        print("\nNo matching sequences found!")
        return
    
    print(f"\nFound {len(sequences)} matching sequence(s)")
    
    # Ask user for confirmation
    if idaapi.ask_yn(idaapi.ASKBTN_YES, f"Found {len(sequences)} sequence(s). Inline all?") != idaapi.ASKBTN_YES:
        print("Operation cancelled by user")
        return
    
    # Inline each sequence
    success_count = 0
    for i, seq in enumerate(sequences):
        print(f"\n[{i+1}/{len(sequences)}] Processing sequence at 0x{seq['mov_ea']:X}")
        try:
            if inline_function(seq):
                success_count += 1
        except Exception as e:
            print(f"Error inlining at 0x{seq['mov_ea']:X}: {e}")
    
    print("\n" + "=" * 60)
    print(f"Completed: {success_count}/{len(sequences)} sequences successfully inlined")
    print("=" * 60)
    
    # Reanalyze the modified areas
    for seq in sequences:
        idc.create_insn(seq['mov_ea'])
    
    print("\nDone! Please refresh the disassembly view if needed.")

# Add required imports that might be missing
try:
    import idautils
except ImportError:
    import ida_utils as idautils

if __name__ == "__main__":
    main()