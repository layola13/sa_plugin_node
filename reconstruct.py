import sys
import re
import os
import uuid

RESERVED = {"ptr", "u64", "u32", "i32", "i64", "void", "u16", "u8", "i8", "i16", "f32", "f64", "blob_handle", "v128", "bool", "str"}

def to_macro_name(extern_name):
    name = extern_name.replace("sa_node_plugin_", "")
    return "NODE_" + name.upper()

def parse_zig_type(zig_type, name):
    zig_type = zig_type.lower()
    name = name.lower()
    if "?*?*" in zig_type or "?*?[" in zig_type: return "ptr"
    if "?*anyopaque" in zig_type: return "ptr"
    if "?[*]" in zig_type: return "ptr"
    if "ptr" in zig_type or "ptr" in name: return "ptr"
    if "handle" in name or "ch" in name or "ee" in name or "ws" in name or "req" in name or "resp" in name or "client" in name: return "ptr"
    return "u64"

def reconstruct():
    defined_macros = set()
    if os.path.exists("node.sal"):
        with open("node.sal", "r") as f:
            for line in f:
                match = re.search(r"\[MACRO\]\s+([a-zA-Z0-9_]+)", line)
                if match: defined_macros.add(match.group(1).strip())

    node_sai_symbols = set()
    if os.path.exists("node.sai"):
        with open("node.sai", "r") as f:
            for line in f:
                match = re.search(r"@extern\s+([a-zA-Z0-9_]+)", line)
                if match: node_sai_symbols.add(match.group(1).strip())

    exports = []
    seen_names = set()
    for root, dirs, files in os.walk("src"):
        for file in files:
            if file.endswith(".zig"):
                with open(os.path.join(root, file), "r") as f:
                    content = f.read()
                    matches = re.finditer(r"pub\s+export\s+fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*([a-zA-Z0-9_!^?*\[\]\s]+)\s*\{", content, re.DOTALL)
                    for m in matches:
                        name = m.group(1)
                        if not name.startswith("sa_node_plugin_"): continue
                        if name in seen_names: continue
                        seen_names.add(name)
                        
                        args_raw = m.group(2)
                        ret_raw = m.group(3).strip()
                        
                        args = []
                        for arg_pair in args_raw.split(","):
                            arg_pair = arg_pair.strip()
                            if not arg_pair: continue
                            if ":" not in arg_pair: continue
                            arg_name, arg_zig_type = arg_pair.split(":", 1)
                            arg_name = arg_name.strip()
                            if arg_name in RESERVED: arg_name = "arg_" + arg_name
                            is_out = arg_name.startswith("out_") or "?*?*" in arg_zig_type or "?*?[" in arg_zig_type
                            sa_type = parse_zig_type(arg_zig_type, arg_name)
                            args.append({"name": arg_name, "is_out": is_out, "type": sa_type})
                            
                        ret_type = parse_zig_type(ret_raw, "status")
                        if ret_raw == "void": ret_type = "u32"
                        exports.append({"name": name, "args": args, "ret": ret_type})

    with open("node_extra.sai", "w") as f:
        f.write("// Auto-generated extra SAI\n")
        for e in exports:
            if e["name"] not in node_sai_symbols:
                args_sai = []
                for a in e["args"]:
                    prefix = "&" if a["is_out"] else ""
                    args_sai.append(f"{prefix}{a['name']}: {a['type']}")
                f.write(f"@extern {e['name']}(" + ", ".join(args_sai) + f") -> {e['ret']}\n")

    macro_usage = {}
    if os.path.exists("expand_calls.txt"):
        with open("expand_calls.txt", "r") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("EXPAND"): continue
                parts = line.split(" ", 2)
                if len(parts) < 2: continue
                mname = parts[1]
                args_part = parts[2] if len(parts) > 2 else ""
                margs = [a.strip() for a in args_part.split(",") if a.strip()]
                macro_usage[mname] = margs

    with open("node_extra.sal", "w") as f:
        f.write("@import \"node.sai\"\n@import \"node_extra.sai\"\n\n")
        for i, e in enumerate(exports):
            mname = to_macro_name(e["name"])
            if mname in defined_macros: continue
            
            used_params = macro_usage.get(mname, None)
            macro_params = []
            if used_params:
                for j, p in enumerate(used_params):
                    macro_params.append(f"%p_{j}")
            else:
                expected_count = len(e["args"]) + (1 if e["ret"] != "void" else 0)
                macro_params = [f"%p_{j}" for j in range(expected_count)]
            
            expected_count = len(macro_params)
            params_str = ", ".join(macro_params)
            f.write(f"[MACRO] {mname} {params_str}\n" if params_str else f"[MACRO] {mname}\n")
            
            call_args = []
            out_mappings = []
            param_idx = 0
            
            # Map input args
            for a in [arg for arg in e["args"] if not arg["is_out"]]:
                if param_idx < expected_count:
                    call_args.append(macro_params[param_idx])
                    param_idx += 1
                else:
                    call_args.append("0")
            
            status_param_idx = -1
            if param_idx + len([arg for arg in e["args"] if arg["is_out"]]) < expected_count:
                 status_param_idx = expected_count - 1
            
            # Use completely random status register to avoid hyg naming collisions
            rand_id = uuid.uuid4().hex[:8]
            
            # Map output args
            for j, a in enumerate([arg for arg in e["args"] if arg["is_out"]]):
                slot_name = f"__m_slot_{rand_id}_{j}"
                f.write(f"    {slot_name} = stack_alloc 8\n")
                call_args.append(f"&{slot_name}")
                if param_idx < expected_count and param_idx != status_param_idx:
                    out_mappings.append({"slot": slot_name, "param": macro_params[param_idx], "type": a["type"]})
                    param_idx += 1
            
            call_line = f"call @{e['name']}(" + ", ".join(call_args) + ")"
            if status_param_idx != -1:
                dummy_status = f"__m_status_{rand_id}"
                f.write(f"    {dummy_status} = {call_line}\n")
                f.write(f"    !{macro_params[status_param_idx]}\n")
                f.write(f"    {macro_params[status_param_idx]} = add {dummy_status}, 0\n")
                f.write(f"    !{dummy_status}\n")
            else:
                dummy_status = f"__m_status_{rand_id}"
                f.write(f"    {dummy_status} = {call_line}\n")
                f.write(f"    !{dummy_status}\n")
            
            for m in out_mappings:
                dummy_load = f"__m_load_{rand_id}_{m['param'][1:]}"
                f.write(f"    {dummy_load} = load {m['slot']}+0 as {m['type']}\n")
                f.write(f"    !{m['param']}\n")
                f.write(f"    {m['param']} = add {dummy_load}, 0\n")
                f.write(f"    !{dummy_load}\n")
            
            f.write("[END_MACRO]\n\n")

if __name__ == "__main__":
    reconstruct()
