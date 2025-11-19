#!/usr/bin/env python3
"""
DLL Parser and Disassembler
Parses a DLL file, disassembles exported functions, and prints instructions with immediate operands.
"""

import os
import sys
import json
import pefile
import lief
from capstone import *
from capstone.x86 import *

results = []
lief_pe = None

def has_immediate_operand(instruction):
    """
    Check if an instruction has an immediate operand.
    """
    if instruction.mnemonic is None or instruction.mnemonic != 'movabs':
        return False

    for operand in instruction.operands:
        if operand.type == X86_OP_IMM:
            # if abs(operand.value.imm) > 0xFFFFFF:
            return True
    return False

def format_instruction(addr, instruction):
    """
    Format an instruction for display.
    """
    # Get hex bytes
    hex_bytes = ' '.join(f'{b:02x}' for b in instruction.bytes)
    
    # Find immediate operands
    immediates = []
    for operand in instruction.operands:
        if operand.type == X86_OP_IMM:
            val = operand.value.imm & 0xFFFFFFFFFFFFFFFF
            immediates.append(f'0x{val:08X}')
    
    imm_str = f" [IMM: {', '.join(immediates)}]" if immediates else ""
    
    return f"  0x{addr:08x}: {hex_bytes:<20} {instruction.mnemonic:<8} {instruction.op_str:<30}{imm_str}"

def disassemble_function(pe, md, function_rva, function_name, max_instructions=1000000):
    """
    Disassemble a function and return instructions with immediate operands.
    """
    print(f"\n{'='*80}")
    print(f"Function: {function_name}")
    print(f"RVA: 0x{function_rva:08x}")
    print(f"{'='*80}")
    
    try:
        # Convert RVA to file offset
        offset = pe.get_offset_from_rva(function_rva)
        if offset is None:
            print(f"  [!] Could not resolve RVA to file offset")
            return
        
        # Get the section containing this function
        section = None
        for s in pe.sections:
            if s.contains_rva(function_rva):
                section = s
                break
        
        if not section:
            print(f"  [!] Could not find section containing function")
            return
        
        # Read bytes from the function (read a reasonable amount)
        # We'll read up to 1KB or until the section ends
        # l = section.SizeOfRawData - (offset - section.PointerToRawData)
        

        bytes_to_read = 3500 # min(3500, section.SizeOfRawData - (offset - section.PointerToRawData))
        if function_name == "_Z5checkPh":
            bytes_to_read = 100000
        print(f"[*] Estimated bytes to read: {bytes_to_read}")
        function_bytes = pe.get_data(function_rva, bytes_to_read)
        print(f"  Read {len(function_bytes)} bytes from function")
        if not function_bytes:
            print(f"  [!] Could not read function bytes")
            return

        # Disassemble the function
        call_order = []
        instructions_with_imm = []
        instruction_count = 0
        ret_encountered = 0
        seq_pop_count = 0
        prev_instr = None
        rip = function_rva
        for instruction in md.disasm(function_bytes, function_rva):
            instruction_count += 1
            rip += instruction.size

            if function_name == "_Z5checkPh" and len(instructions_with_imm) == 0:
                if  instruction.mnemonic == "mov" and instruction.operands[1].type == X86_OP_MEM and instruction.operands[1].value.mem.disp > 0xFFFF:
                    # print(f"  [*] Found call/mov to non-reg operand: {instruction.mnemonic} {instruction.op_str} -> {instruction.operands[1].value.mem.disp:X}")
                    import_name = get_import_name(instruction.operands[1].value.mem.disp+rip)
                    # print(f"  [*] Found import address: {import_name}")
                    val = import_name
                    call_order.append(val)
                elif instruction.mnemonic == "call" and instruction.operands[0].value.imm > 0xFF:
                    # print(f"  [*] Found: {instruction.mnemonic} {instruction.op_str} -> {instruction.operands[0].value.imm:X}")
                    val = get_exprort_name(instruction.operands[0].value.imm & 0xFFFFFFFFFFFFFFFF)
                    # print(f"  [*] Found export address: {val}")
                    call_order.append(val)
                # print(f"-------------> Call to 0x{val:08X}")
                 
            # Check if instruction has immediate operand
            if has_immediate_operand(instruction):
                instructions_with_imm.append((instruction.address, instruction))
            
            # Stop after a reasonable number of instructions or on RET
            if instruction_count >= max_instructions:
                print("  [!] Reached maximum instruction count, stopping disassembly")
                break
            if instruction.mnemonic == 'pop':
                seq_pop_count += 1
        
            if instruction.mnemonic in ['ret', 'retn'] and seq_pop_count > 0:
                print("  [!] Encountered function epilogue! stopping disassembly")
                break        
            prev_instr = instruction
        

        # Print instructions with immediate operands
        if instructions_with_imm:
            print(f"[*] Instructions disassembled: {instruction_count}")
            print(f"\n  Instructions with immediate operands ({len(instructions_with_imm)} found):")
            print(f"  {'Address':<12} {'Bytes':<20} {'Mnemonic':<8} {'Operands':<30} Immediate Values")
            print(f"  {'-'*90}")
            
            constants = []
            for addr, instr in instructions_with_imm:
                constants.append(instr.operands[1].value.imm & 0xFFFFFFFFFFFFFFFF)
                print(format_instruction(addr, instr))

            if len(constants) > 4:
                ftype = 1
            elif len(constants) == 4:
                if instruction_count < 100:
                    ftype = 2
                else:
                    ftype = 3

            print(f"[*] Function type: {ftype}")
            result = {
                'func_name': function_name,
                'func_type': ftype,
                'rva': function_rva,
                'constants': constants
            }
            if len(call_order) > 0:
                result['call_order'] = call_order
            results.append(result)
        else:
            print(f"  No instructions with immediate operands found in first {instruction_count} instructions")
            
    except Exception as e:
        print(f"  [!] Error disassembling function: {e}")

def parse_dll(dll_path):
    """
    Parse a DLL file and disassemble its exported functions.
    """
    try:
        # Load the DLL
        print(f"Loading DLL: {dll_path}")
        pe = pefile.PE(dll_path)
        
        # Detect architecture
        machine = pe.FILE_HEADER.Machine
        if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            arch = CS_ARCH_X86
            mode = CS_MODE_64
            arch_name = "x64"
        elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            arch = CS_ARCH_X86
            mode = CS_MODE_32
            arch_name = "x86"
        else:
            print(f"Unsupported architecture: 0x{machine:04x}")
            return
        
        print(f"Architecture: {arch_name}")
        
        # Initialize Capstone disassembler with detailed mode
        md = Cs(arch, mode)
        md.detail = True  # Enable detailed mode to get operand information
        
        # Check if DLL has exports
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("No exports found in this DLL")
            return
        
        print(f"\nFound {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)} exported functions")
        
        # Process each exported function
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # Skip forwarded exports
            if exp.forwarder:
                continue
            
            # Get function name
            if exp.name:
                func_name = exp.name.decode('utf-8', errors='ignore')
            else:
                func_name = f"Ordinal_{exp.ordinal}"
            
            # if (not "_Z5checkPh" in func_name): # and (not "f66793833099044736703" in func_name): # and (not "f05428665405949737414" in func_name): # 
            #     continue

            # Disassemble the function
            disassemble_function(pe, md, exp.address, func_name)
        
        # Clean up
        pe.close()
        
    except FileNotFoundError:
        print(f"Error: File '{dll_path}' not found")
    except pefile.PEFormatError:
        print(f"Error: '{dll_path}' is not a valid PE/DLL file")
    except Exception as e:
        print(f"Error: {e}")


def get_import_name(func_addr):
    global lief_pe
    for imp in lief_pe.imported_functions:
        if func_addr == imp.address:
            return f"{imp.name}"
    return None

def get_exprort_name(func_addr):
    global lief_pe
    for exp in lief_pe.exported_functions:
        if func_addr == exp.address:
            return f"{exp.name}"
    return None

def main():
    """
    Main function to handle command-line arguments.
    """
    if len(sys.argv) != 2:
        print("Usage: python dll_disassembler.py <path_to_dll>")
        print("\nExample:")
        print("  python dll_disassembler.py C:\\Windows\\System32\\kernel32.dll")
        sys.exit(1)
    

    global lief_pe
    dll_path = sys.argv[1]
    lief_pe = lief.PE.parse(dll_path)
    parse_dll(dll_path)

    with open(f"{os.path.basename(dll_path)}_constants.json", "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[*] Results saved to {os.path.basename(dll_path)}_constants.json")

if __name__ == "__main__":
    main()