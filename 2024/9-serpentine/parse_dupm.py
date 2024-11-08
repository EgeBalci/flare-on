#!/bin/env python

import re

# Define the function delimiter string
FUNC_DELIMITER = "jmp"
EXE_PATH="serpentine_clean.exe"
OUTPUT_FILE="decode.py"
INPUT_FILE="unpacked.asm"
INPUT="1234567890ABCDEFGHJKLMNOPRSTWXYZ"

MASKS = {
    0: "0xFFFFFFFFFFFFFF00",
    1: "0xFFFFFFFFFFFF00FF",
    2: "0xFFFFFFFFFF00FFFF",
    3: "0xFFFFFFFF00FFFFFF",
    4: "0xFFFFFF00FFFFFFFF",
    5: "0xFFFF00FFFFFFFFFF",
    6: "0xFF00FFFFFFFFFFFF",
    7: "0x00FFFFFFFFFFFFFF",
}

MAP_ADDRS = []
FIRST_INP_MUL = True

# Predefined regex patterns
patterns = {
    "INP-MUL": re.compile(r'mul ', re.MULTILINE),  # Example pattern 
    "INP-XOR": re.compile(r'xor ', re.MULTILINE),  # Example pattern    
    "INP-SUB": re.compile(r'sub +[a-z0-9]{2,4}, \[', re.MULTILINE),  # Example pattern    
    "INP-ADD": re.compile(r'add +[a-z0-9]{2,4}, \[', re.MULTILINE),  # Example pattern    
    "STG-END": re.compile(r'test ', re.MULTILINE),  # Example pattern    
    "CON-ADD": re.compile(r'shl.+\n.+add', re.MULTILINE),  # Example pattern 1
    "CON-SUB": re.compile(r'shl.+\n.+sub +\[', re.MULTILINE),  # Example pattern 
    "MAP-SWP": re.compile(r'shl.+\n.+not', re.MULTILINE),  # Example pattern 
    "MAP-MOV": re.compile(r'mov +[a-z0-9]{1,3}[bl], \[.+\n.+mov +[a-z0-9]{1,3}[bl], [a-z0-9]{1,3}[bl]', re.MULTILINE),  # Example pattern 
}

def read_and_split_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            # Split the content based on FUNC_DELIMITER
            parts = content.split(FUNC_DELIMITER)
            return parts
    except Exception as error:
        print(f"[-] {error}")
        return []

def get_reg_value(line, reg):
    pattern = re.compile(f"{reg.upper()}=0X([0-9A-Fa-f]+)")
    match = pattern.search(line)
    if match:
        val_str = match.group(1)
        return int(val_str, 16)
    else:
        print(f"line = {line} | reg = {reg}")
        raise ValueError("[-] Failed getting register value!")

def get_map_addr(part):
    addr = 0
    ref_mov_pattern = re.compile(r'mov +([a-z0-9]{2,4}), [0-9A-F]+h.+\n.+add +[a-z0-9]{2,4}, [0-9A-F]+h.+\n.+mov.+\n.+add.+')
    ref_mov_match = ref_mov_pattern.search(part)    
    if ref_mov_match:
        reg = ref_mov_match.group(1)
        addr = get_reg_value(ref_mov_match.group().splitlines()[-1], reg)
    else:
        mov_pattern = re.compile(r'mov +[a-z0-9]{1,3}[bl], \[([a-z0-9]{2,4})(\+0|)\].+')
        add_pattern = re.compile(r'add +[a-z0-9]{2,4}, \[.+')
        # Search for the pattern in the instruction string
        mov_match = mov_pattern.search(part)
        add_match = add_pattern.search(part)
        if mov_match and add_match:
            reg = mov_match.group(1)
            mov_val_str = get_reg_value(mov_match.group(), reg) 
            add_val_str = get_reg_value(add_match.group(), reg) 
            addr = abs(mov_val_str - add_val_str)        
        else:
            print(part)
            raise ValueError("[-] Invalid MAP-SWP part!")

    if addr > 0x140899000 or addr < 0x140022000: 
        print(part)
        raise ValueError(f"[-] Invalid map address: {hex(addr)}")
    
    if (addr != 0x140898870 and addr != 0x140898770) and (addr & 0xFF) != 0xC0:
        raise ValueError(f"[-] Invalid map address: {hex(addr)}")
    return addr

def get_shift_key(part):
    pattern = re.compile(r'shl.+, (0x[0-9A-Fa-f]+|\d+)', re.IGNORECASE)
    # Search for the pattern in the instruction string
    match = pattern.search(part)
    if match:
        operand_str = match.group(1)
        return int(operand_str, 16)
    else:
        raise ValueError("[-] Invalid SHL instruction format")

def get_input_index(part):
    pattern = re.compile(r'mul .+', re.IGNORECASE)
    # Search for the pattern in the instruction string
    match = pattern.search(part)
    if match:
        rax = get_reg_value(match.group(), "RAX") 
        for i, c in enumerate(INPUT):
            if ord(c) == rax:
                return i
        raise ValueError("[-] Input byte not in input string!")
    else:
        raise ValueError("[-] Invalid INP-MUL part!")

def get_mul_constant(part):
    push_pattern = re.compile(r'push\s+([a-z0-9]{2,4})', re.IGNORECASE)
    # Search for the pattern in the instruction string
    match = push_pattern.search(part)
    if match:
        reg = match.group(1)
        val_pattern = re.compile(f'push.+{reg.upper()}=0x([0-9A-Fa-f]+),', re.IGNORECASE)
        val_match = val_pattern.search(part)
        if val_match:
            val_str = val_match.group(1) 
            return int(val_str, 16)
        else:
            raise ValueError("[-] Missing register values!")
    else:
        raise ValueError("[-] Invalid INP-MUL part!")


def generate_con_add_seq(part):
    sk = get_shift_key(part)
    map_addr = get_map_addr(part)
    MAP_ADDRS.append(map_addr)
    print(f"[+] Found new map address: {hex(map_addr)}")
    index = f"(base >> {sk-8}) & 0xFF"
    return f"base = (0xFFFFFFFFFFFFFFFF & (base + (map_{map_addr:X}[{index}] << {sk})))"

def generate_con_sub_seq(part):
    sk = get_shift_key(part)
    map_addr = get_map_addr(part)
    MAP_ADDRS.append(map_addr)
    print(f"[+] Found new map address: {hex(map_addr)}")
    index = f"(base >> {sk-8}) & 0xFF"
    return f"base = (0xFFFFFFFFFFFFFFFF & (base - (map_{map_addr:X}[{index}] << {sk})))"

def generate_map_swap_seq(part):
    global MAP_ADDRS
    sk = get_shift_key(part)
    map_addr = get_map_addr(part)
    MAP_ADDRS.append(map_addr)
    print(f"[+] Found new map address: {hex(map_addr)}")
    index = f"(base >> {sk}) & 0xFF"
    return f"base = ((base & {MASKS[sk/8]}) | (map_{map_addr:X}[{index}] << {sk}))"

def generate_map_mov_seq(part):
    global MAP_ADDRS
    map_addr = get_map_addr(part)
    MAP_ADDRS.append(map_addr)
    print(f"[+] Found new map address: {hex(map_addr)}")
    index = f"base & 0xFF"
    return f"base = ((base & {MASKS[0]}) | map_{map_addr:X}[{index}])"

def generate_input_mul_seq(part):
    input_index = get_input_index(part)
    multiplier = get_mul_constant(part)
    var = "mul_res"
    global FIRST_INP_MUL
    if FIRST_INP_MUL:
        var = "base"
        FIRST_INP_MUL = False
    return f"{var} = (0xFFFFFFFFFFFFFFFF & (ord(input[{input_index}])*{hex(multiplier)}))"

def generate_input_xor_seq():
    return f"base = (base ^ mul_res)"

def generate_input_sub_seq():
    return f"base = 0xFFFFFFFFFFFFFFFF & (base - mul_res)"

def generate_input_add_seq():
    return f"base = 0xFFFFFFFFFFFFFFFF & (base + mul_res)"

def process_dump(parts):
    stage=1

    global FIRST_INP_MUL
    file = open(OUTPUT_FILE, 'a')
    file.write(f"\n\ninput=\"{INPUT}\"\n\n")
    file.write(f"def stage_{stage}():\n")

    for i, part in enumerate(parts):
        if patterns["STG-END"].search(part):
            print(f"[+] Reached the end of stage {stage}!")
            FIRST_INP_MUL = True
            format_str = "{hex(base)}"
            file.write(f"\tprint(f\"[+] STAGE-{stage}: {format_str}\")\n")
            file.write(f"\treturn base\n")
            stage += 1
            if stage != 33:
                file.write(f"\n\ndef stage_{stage}():\n")
            else:
                file.write(f"\n\nstage_1()\n")

            # file.write(f"\tbase = 0\n")
        elif patterns["INP-MUL"].search(part):
            print(f"[*] Pocessing input mul sequence...")
            seq = generate_input_mul_seq(part)
            file.write(f"\t{seq}\n")
        elif patterns["INP-XOR"].search(part):
            print(f"[*] Pocessing input mul sequence...")
            seq = generate_input_xor_seq()
            file.write(f"\t{seq}\n")
        elif patterns["INP-SUB"].search(part):
            print(f"[*] Pocessing input sub sequence...")
            seq = generate_input_sub_seq()
            file.write(f"\t{seq}\n")
        elif patterns["CON-ADD"].search(part):
            print(f"[*] Pocessing conditinal add sequence...")
            # seq = generate_con_add_seq(part)
            # file.write(f"\t{seq}\n")
        elif patterns["CON-SUB"].search(part):
            print(f"[*] Pocessing conditinal sub sequence...")
            # seq = generate_con_sub_seq(part)
            # file.write(f"\t{seq}\n")
        elif patterns["MAP-SWP"].search(part):
            print(f"[*] Pocessing map swap sequence...")
            seq = generate_map_swap_seq(part)
            file.write(f"\t{seq}\n")
        elif patterns["MAP-MOV"].search(part):
            print(f"[*] Pocessing map mov sequence...")
            seq = generate_map_mov_seq(part)
            file.write(f"\t{seq}\n")
        elif patterns["INP-ADD"].search(part):
            print(f"[*] Pocessing input add sequence...")
            seq = generate_input_add_seq()
            file.write(f"\t{seq}\n")
        else:
            print(f"[*] Skipping insignificant part {i} ...")
    file.close()

    print(f"\n\n[*] Switching to data map extraction...")
    global MAP_ADDRS
    MAP_ADDRS = sorted(set(MAP_ADDRS))
    print(f"[+] Found {len(MAP_ADDRS)} map addresses!")

    ds_offset = 0x20400
    ds_vma = 0x140022000

    file = open(OUTPUT_FILE, "r")
    exe = open(EXE_PATH, "rb")
    data = exe.read()
    
    map_arrays = ""
    for addr in MAP_ADDRS:
        offset = ds_offset + (addr-ds_vma)
        map = bytearray(256)
        if addr != 0x140898770 and addr != 0x140898870: 
            map = data[offset:offset+0xFF+1]
        byte_array = [f"0x{byte:02X}" for byte in map]
        map_arrays += f"map_{addr:X} = [{", ".join(byte_array)}]\n"   


    # print(map_arrays)
    file_data = file.read()
    file.close()
    final = map_arrays+file_data
    file = open(OUTPUT_FILE, "w")
    file.write(final) 
    file.close()
    print("[##### ALL DONE ####]")


def main(file_path):
    # Step 1: Read and split the file
    print(f"[*] Starting...")
    parts = read_and_split_file(file_path)
    if parts:
        print("[*] Processing file...")
        process_dump(parts)
    else:
        print("[-] Invalid dump file!")

# Example usage
if __name__ == "__main__":
    main(INPUT_FILE)
