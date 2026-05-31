import re
import os

def fix_sal(filename):
    if not os.path.exists(filename): return
    with open(filename, "r") as f:
        content = f.read()
        
    # Pattern: [MACRO] NAME %p1, ... \n ... call @sa_node_plugin_.*_free(%p1, ...)
    # Add !%p1 after the call
    
    def repl(m):
        header = m.group(1)
        params = m.group(2).split(",")
        body = m.group(3)
        macro_name = m.group(1).strip()
        
        if any(keyword in macro_name for keyword in ["FREE", "DESTROY", "CLOSE", "END", "UNLINK", "RMDIR"]):
            # Find the handle param (usually the first one)
            if params:
                handle_param = params[0].strip()
                if "!%s" % handle_param not in body:
                    # Add ! before [END_MACRO]
                    return "[MACRO] %s %s\n%s    !%s\n[END_MACRO]" % (header, ",".join(params), body, handle_param)
        return m.group(0)

    new_content = re.sub(r"\[MACRO\]\s+([a-zA-Z0-9_]+)\s+([^ \n][^\n]*)\n(.*?)\s*\[END_MACRO\]", repl, content, flags=re.DOTALL)
    
    with open(filename, "w") as f:
        f.write(new_content)

if __name__ == "__main__":
    fix_sal("node.sal")
    fix_sal("node_extra.sal")
