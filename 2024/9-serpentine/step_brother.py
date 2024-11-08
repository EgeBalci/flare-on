import idaapi
import idc
import ida_dbg
import ida_bytes
import ida_kernwin
import ida_lines
import ida_auto
import time
import re

# base_addr = 0
# inst_db_size = 20
EXE="C:\\Users\\user\\Desktop\\serpentine_clean.exe" # !!! CHANGE THIS !!!
SET_ZF=False
OUT_FILE="unpacked.asm"

FILTERED_EXCEPTION_HANDLER=0x00000001400010B0
NTDLL_ANCHOR_POINT_INST="call    rax"
TARGET_SEQ="89050100000058" # mov cs:dword_6CB4D49, eax; pop rax
LDMXCSR_RGX=r'(ldmxcsr.+) (r[a-z0-9]{2})$'


# CTX_FIX_TABLE = {
#     r'.+\[[a-z0-9]{2,4}\+28h\]': '',
#     r'\[[a-z0-9]{2,4}\+78h\]': 'rax',
#     r'\[[a-z0-9]{2,4}\+90h\]': 'rbx',
#     r'\[[a-z0-9]{2,4}\+80h\]': 'rcx',
#     r'\[[a-z0-9]{2,4}\+88h\]': 'rdx',
#     r'\[[a-z0-9]{2,4}\+0B0h\]': 'rdi',
#     r'\[[a-z0-9]{2,4}\+0A8h\]': 'rsi',
#     r'\[[a-z0-9]{2,4}\+0A0h\]': 'rbp',
#     r'\[[a-z0-9]{2,4}\+0B8h\]': 'r8',
#     r'\[[a-z0-9]{2,4}\+0C0h\]': 'r9',
#     r'\[[a-z0-9]{2,4}\+0C8h\]': 'r10',
#     r'\[[a-z0-9]{2,4}\+0D0h\]': 'r11',
#     r'\[[a-z0-9]{2,4}\+0D8h\]': 'r12',
#     r'\[[a-z0-9]{2,4}\+0E0h\]': 'r13',
#     r'\[[a-z0-9]{2,4}\+0E8h\]': 'r14',
#     r'\[[a-z0-9]{2,4}\+0F0h\]': 'r15',
#     r'ldmxcsr dword ptr \[[a-z0-9]{2,4}\+34h\]':'',
#     r'mov     (r[a-z0-9]{2,3}), \[[a-z0-9]{2,4}\+34h\]': '*',
# }

# x86_registers = [
#     # 8-bit registers
#     "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", 
#     "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    
#     # 16-bit registers
#     "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", 
#     "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    
#     # 32-bit registers
#     "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", 
#     "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    
#     # 64-bit registers
#     "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", 
#     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
# ]

# x86_64_registers = [    
#     # 64-bit registers
#     "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", 
#     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
# ]


def get_current_ip():
    ida_dbg.refresh_debugger_memory()
    idaapi.invalidate_dbgmem_config()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    rip = ida_dbg.get_reg_val("rip")
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    return rip

# Function to get the current instruction pointer
def get_current_inst():
    current_ip = get_current_ip()
    current_inst = idc.GetDisasm(current_ip)
    if "db " in current_inst:
        print(f"[-] Failed decoding instruction at {hex(current_ip)}! Retrying...")
        # idc.create_insn(current_ip)
        ida_bytes.del_items(current_ip, 0, 10)
        ida_auto.auto_recreate_insn(current_ip)
        idc.auto_wait()  # Wait for auto-analysis to complete
        time.sleep(0.1)
        current_inst = get_current_inst()
    return current_inst

def set_zero_flag():
    ida_dbg.set_reg_val("ZF", 1)
    idc.auto_wait()
    idaapi.process_ui_action("update")  # Process UI events to keep IDA responsive
    time.sleep(0.5)
    if ida_dbg.get_reg_val("ZF") != 1:
        print("[-] Failed setting zero flag! Retrying...")
        set_zero_flag()
    print("[+] Zero flag set!")


def find_ntdll_anchor_point():
    idaapi.add_bpt(FILTERED_EXCEPTION_HANDLER)
    print(f"[+] Breakpoint set at {hex(FILTERED_EXCEPTION_HANDLER)}")    
    print("[+] Resuming...")
    idaapi.continue_process()
    
    current_ip = get_current_ip()
    current_inst = get_current_inst()
    print(f"[*] Stepping until we find the NTDLL anchor point...")
    while (current_inst !=  NTDLL_ANCHOR_POINT_INST):
        ida_dbg.request_step_into()
        ida_dbg.run_requests()
        idc.auto_wait()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        idaapi.process_ui_action("update")  # Process UI events to keep IDA responsive
        time.sleep(0.01)
        # print(f"[*]> {hex(current_ip)}: {current_inst}")
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        current_ip = get_current_ip()
        current_inst = get_current_inst()        

    print(f"[+] Found NTDLL anchor point at: {hex(current_ip)}")
    idaapi.del_bpt(FILTERED_EXCEPTION_HANDLER)
    print(f"[+] Breakpoint removed at {hex(FILTERED_EXCEPTION_HANDLER)}")
    idaapi.add_bpt(current_ip) # call    rax
    print(f"[+] Breakpoint set at {hex(current_ip)}")


def step_brother():
    """
    Run the debugger with single-step execution until the specified instruction is hit.

    :param target_ea: Target effective address (EA) of the instruction to stop at.
    """
    target_seq_arr = bytearray.fromhex(TARGET_SEQ)
    target_seq_size = len(target_seq_arr)

    def step_in(count):
        global SET_ZF
        current_ip = get_current_ip()
        # insn = idaapi.insn_t()
        # idaapi.decode_insn(insn, current_ip)
        current_inst = get_current_inst()
        for _ in range(count):     
            if SET_ZF:
                set_zero_flag()
                SET_ZF=False
                #exit()
            ida_dbg.request_step_into()
            ida_dbg.run_requests()
            idc.auto_wait()
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
            idaapi.process_ui_action("update")  # Process UI events to keep IDA responsive
            time.sleep(0.01)
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
            current_ip = get_current_ip()
            current_inst = get_current_inst()
            if "test" in current_inst or "cmovnz" in current_inst:
                set_zero_flag()
                SET_ZF=True
        return current_ip, current_inst

    def get_used_regs(inst):
        regs = []
        for reg in x86_registers:
            if reg in inst:
                regs.append(reg)
        return regs

    def write_current_inst():
        current_ip = get_current_ip()
        inst = get_current_inst()
        indent = " "*(36-len(inst))
        values = "; "
        for reg in x86_64_registers:
            val = hex(ida_dbg.get_reg_val(reg)).upper()
            values += f"{reg.upper()}={val},"
        print(f"[+]> {hex(current_ip)}: {inst}{indent}\t{values}")
        f = open(OUT_FILE, "a")
        f.write(f"unk_{hex(current_ip)}:\t{str(inst)}{indent}\t{values}\n")
        f.close()

    # Start single-stepping
    print(f"[*] Starting single-step execution until '{TARGET_SEQ}' is reached.")    
    while True:
        # Request a single step
        current_ip, current_inst = step_in(1)

        # Check if the debugger is still running
        if not ida_dbg.is_debugger_on():
            print("[-] Debugger stopped unexpectedly.")
            break

        if current_ip != 0x00007FF8453551DD and current_ip > 0x000000007FFE5000:
            print(f"[!] RIP is outside the stack bounds -> {hex(current_ip)}")
            print(f"[+] Exiting...")
            break

        current_seq = ida_bytes.get_bytes(current_ip, target_seq_size)

        # Check if we've reached the target
        if current_seq == target_seq_arr:
            print(f"[!]> {hex(current_ip)} ======================================> [!! TARGET SEQUENCE REACHED !!]")
            # move two steps
            current_ip, current_inst = step_in(2)
            # get decoded inst...
            write_current_inst()

            if "jmp" in current_inst:
                current_ip, current_inst = step_in(3)
                # print(f"[*]> {hex(current_ip)}: {current_inst}")  
            else:
                print("[*] Stepping until return...")
                while "ret" not in current_inst: # Find next ret
                    current_ip, current_inst = step_in(1)
                    # print(f"[*]> {hex(current_ip)}: {current_inst}")     
                current_ip, current_inst = step_in(1)
            
            # Return here...
            print("[*] Stepping until call...")
            while "call" not in current_inst: # find next call
                write_current_inst()
                current_ip, current_inst = step_in(1)
            # break
    # print(f"[!] Max step count {step_count} reached! Exiting...")
# Example usage:


print("[*] STARTING ...")
if not ida_dbg.is_debugger_on():
    idaapi.add_bpt(0x140001649) # call    cs:lpAddress
    print("[+] Breakpoint set at 0x140001649")
    print("[*] Starting EXE...")
    idaapi.start_process(EXE, "11223344556677889900AABBCCDDEEFF", "")
    find_ntdll_anchor_point()
    # idaapi.add_bpt(0x00007FF8453551DD) # ntdll.dll -> RtlVirtualUnwind !!! CHANGE THIS !!!
    # print("[*] Breakpoint set at 0x00007FF8453551DD")
    # print("[+] Resuming...")
    # idaapi.continue_process()

step_brother()
# run_until_seq(5000000000) 
# run_until_seq("4d85f6", 1000000) # mov cs:dword_6CB4D49, eax; pop ra
