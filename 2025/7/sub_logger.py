import idaapi
import idautils
import idc
import datetime
import ida_nalt

# Constants
EXE_PATH="hopeanddreams.exe"
LOG_FILE = f"{EXE_PATH}_func_trace.log"
ONLY_STRINGS=False
_IMAGE_BASE=0x140000000

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

def get_subroutines():
    """Get all functions with names starting with 'sub_' sorted by size"""
    sub_functions = []
    
    # Iterate through all functions
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if func_name and func_name.startswith("sub_"):
            # Calculate function size
            func_start = func_ea
            func_end = idc.find_func_end(func_ea)
            
            if func_end != idc.BADADDR:
                func_size = func_end - func_start
                sub_functions.append((func_ea, func_name, func_size))
                print(f"Found {func_name} at 0x{func_ea:X} (size: {func_size} bytes)")
            else:
                print(f"Warning: Could not determine size of function {func_name}")
    
    # Sort by function size (largest first)
    sub_functions.sort(key=lambda x: x[2], reverse=True)
    
    print(f"\nFound {len(sub_functions)} functions starting with 'sub_'")
    return sub_functions

def get_ret_address(func_addr):
    """
    Silent version that returns the final 'ret' instruction address without printing.
    
    Args:
        func_addr (int): Address of the function to analyze
        
    Returns:
        int: Address of the final ret instruction, or None if not found or invalid function
    """
    
    # Validate that the address is within a function
    func = ida_funcs.get_func(func_addr)
    if not func:
        return None
    
    # Get function boundaries
    func_start = func.start_ea
    func_end = func.end_ea
    
    # List to store all ret instruction addresses
    ret_addresses = []
    
    # Scan through all instructions in the function
    ea = func_start
    while ea < func_end:
        # Get the mnemonic of the current instruction
        mnem = idc.print_insn_mnem(ea).upper()
        
        # Check if it's a ret instruction
        if mnem.startswith("RET"):
            ret_addresses.append(ea)
        
        # Move to next instruction
        ea = idc.next_head(ea)
        if ea == idc.BADADDR:
            break
    
    # Return the final (last) ret instruction address
    return ret_addresses[-1] if ret_addresses else None



# Callback function that triggers when a breakpoint is hit
class MyBreakpointHandler(idaapi.DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        ida_dbg.refresh_debugger_memory()
        idaapi.invalidate_dbgmem_config()
        image_base = ida_nalt.get_imagebase()
        regs = ["rax", "rcx", "rdx", "r8", "r9"]

        ctx = {}
        no_string = True
        for r in regs:
            r_val = idc.get_reg_value(r)
            r_str = read_string(r_val)
            if r_str is None:
                r_str = ""
            else:
                no_string = False
            ctx[r] = {'val': r_val, 'str': r_str}

        if ONLY_STRINGS and no_string:
            idaapi.continue_process()            
            return 0

        func_name = idc.get_func_name(ea)
        if not func_name:
            func_name = "Unknown"

        rva = _IMAGE_BASE+abs(ea-image_base)
        log = f"[0x{ea:X}] (sub_{rva:X})> RCX: 0x{ctx['rcx']['val']:X} {ctx['rcx']['str']} - RDX: 0x{ctx['rdx']['val']:X} {ctx['rdx']['str']} - R8: 0x{ctx['r8']['val']:X} {ctx['r8']['str']} - R9: 0x{ctx['r9']['val']:X} {ctx['r9']['str']}"
        inst = get_current_inst()
        if "ret" in inst:
            log = f"[0x{ea:X}] (sub_{rva:X})> RET - RAX: 0x{ctx['rax']['val']:X} {ctx['rax']['str']}"

        print(log)
        with open(LOG_FILE, "a") as f:
            f.write(log+"\n")
            f.close()
            idaapi.continue_process()
        return 0

# Function to check if the register value is pointing to a null-terminated string
def read_string(addr):
    try:
        s = idc.get_strlit_contents(addr, -1, idc.STRTYPE_C).decode()
        if len(s) < 3 and not s.isprintable():
            return None
        return f"('{s}')"
    except Exception:
        return None

# Function to set breakpoints on all eligible functions
def set_breakpoints(top_n):
    # Get all functions starting with "sub_" sorted by size
    subs = get_subroutines()
    if not subs:
        print("No functions starting with 'sub_' found!")
        return 0

    top_functions = subs[:top_n]
    actual_count = len(top_functions)
    
    print(f"\nAnalyzing top {actual_count} largest 'sub_' functions:")
    if actual_count < top_n:
        print(f"Note: Only {actual_count} 'sub_' functions found (less than {top_n})")

    for func_ea, func_name, func_size in top_functions:
        print(f"[*] Setting breakpoint at: {func_name}")
        idaapi.add_bpt(func_ea, 0)
        idaapi.enable_bpt(func_ea, True)
        ret_addr = get_ret_address(func_ea)
        if ret_addr is not None:
            idaapi.add_bpt(ret_addr, 0)
            idaapi.enable_bpt(ret_addr, True)

if __name__ == "__main__":
    log_file=open(LOG_FILE, "w")
    log_file.write(f"[*] Time: {datetime.datetime.now()}\n")
    log_file.write("[*] Starting trace...\n\n")
    _IMAGE_BASE = ida_nalt.get_imagebase()
    set_breakpoints(1200)
    print("[+] All breakpoints set!")
    # Start the debugger
    hooks = MyBreakpointHandler()
    hooks.hook()
    idaapi.start_process(EXE_PATH, "", "")

