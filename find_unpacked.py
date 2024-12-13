import idaapi
import idautils
import idc

def detect_jump_to_register():
    results = []
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        func_start = func.start_ea
        func_end = func.end_ea

        # Look at the last instruction in the function
        last_instr_ea = idc.prev_head(func_end)
        if idc.print_insn_mnem(last_instr_ea) == "jmp":
            # Check if the operand is a register
            if idc.get_operand_type(last_instr_ea, 0) == idc.o_reg:
                results.append((last_instr_ea, idc.print_operand(last_instr_ea, 0)))
    

    if results:
        print("Potential jumps to registers detected:")
        for addr, reg in results:
            print(f"At {hex(addr)} jumping to {reg}")
    else:
        print("No jumps to registers detected.")


if __name__ == "__main__":
    detect_jump_to_register()
