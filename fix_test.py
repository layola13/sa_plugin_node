import re
import os

def fix_test(filename):
    with open(filename, "r") as f:
        lines = f.readlines()
        
    new_lines = []
    live_regs = set()
    
    for line in lines:
        m = re.search(r"EXPAND\s+([a-zA-Z0-9_]+)\s+(.*)", line)
        if m:
            args_part = m.group(2)
            args = [a.strip() for a in args_part.split(",") if a.strip()]
            # Consume any live registers that are about to be reassigned in the macro
            # Heuristic: all macro parameters are potential outputs/reassignments
            for a in args:
                if a in live_regs and not a.isdigit() and not a.startswith("S_"):
                    new_lines.append(f"    !{a}\n")
                    live_regs.remove(a)
            
            # After expansion, we assume all args become live
            for a in args:
                if not a.isdigit() and not a.startswith("S_"):
                    live_regs.add(a)
        
        # Also handle manual assignments and consumes
        if " = " in line:
            reg = line.split("=")[0].strip()
            if reg in live_regs:
                new_lines.append(f"    !{reg}\n")
            live_regs.add(reg)
            
        if line.strip().startswith("!"):
            reg = line.strip()[1:].strip()
            if reg in live_regs:
                live_regs.remove(reg)
                
        if line.strip().startswith("@test") or line.strip().startswith("@main"):
            live_regs.clear()
            
        new_lines.append(line)
        
    with open(filename, "w") as f:
        f.writelines(new_lines)

if __name__ == "__main__":
    fix_test("tests/node_plugin_unit_test.sa")
