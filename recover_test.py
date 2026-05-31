import sys
import re

def recover_test():
    with open("expand_calls.txt", "r") as f:
        lines = f.readlines()

    output = ["// Minimal Node plugin unit tests\n@import \"../node.sal\"\n@import \"../node_extra.sal\"\n"]
    
    # Common constants
    output.append("@const S_SHA256 = utf8:\"sha256\"")
    output.append("@const S_HELLO = utf8:\"hello\"")
    output.append("@const S_SECRET = utf8:\"secret123\"")
    output.append("@const S_MSG = utf8:\"test msg\"")
    output.append("@const S_URL = utf8:\"https://example.com/path?q=1\"")
    output.append("@const S_DOMAIN = utf8:\"example.com\"")
    output.append("@const S_ENCODED = utf8:\"hello%20world\"")
    output.append("@const S_KEY = utf8:\"SA_TEST_KEY\"")
    output.append("@const S_VAL = utf8:\"test_value\"")
    output.append("@const S_IP4 = utf8:\"127.0.0.1\"")
    output.append("@const S_IP6 = utf8:\"::1\"")
    output.append("@const S_NOTIP = utf8:\"not-ip\"")
    output.append("@const S_PATH = utf8:\"/usr/local/bin/test.txt\"")
    output.append("@const S_SLASH = utf8:\"/\"")
    output.append("@const S_FROM = utf8:\"/usr/local/bin\"")
    output.append("@const S_TO = utf8:\"/usr/local/share\"")
    output.append("@const S_FMT = utf8:\"hello %s\"")
    output.append("@const S_ARGS = utf8:\"[\\\"world\\\"]\"")
    output.append("@const S_JSON7 = utf8:\"{\\\"a\\\":1}\"")
    output.append("@const S_VT = utf8:\"\\x1b[31mred\\x1b[0m\"")
    output.append("@const S_LOG = utf8:\"log msg\"")
    output.append("@const S_WARN4 = utf8:\"warn\"")
    output.append("@const S_ERR5 = utf8:\"error\"")
    output.append("@const S_DBG = utf8:\"debug\"")
    output.append("@const S_INF = utf8:\"info\"")
    output.append("@const S_DIR = utf8:\"obj\"")
    output.append("@const S_TRC = utf8:\"trace\"")
    output.append("@const S_TBL = utf8:\"{}\"")
    output.append("@const S_LBL = utf8:\"cnt1\"")
    output.append("@const S_CAT = utf8:\"test\"")
    output.append("@const S_CHAN = utf8:\"test.ch\"")
    output.append("@const S_ORD = utf8:\"ipv4first\"\n")

    output.append("@main() -> i32:")
    output.append("L_ENTRY:")
    
    # Just run a few standard ones to confirm native & VM works
    output.append("    p = add 0, 0")
    output.append("    l = add 0, 0")
    output.append("    s = add 0, 0")
    output.append("    EXPAND NODE_OS_CPUS p, l, s")
    output.append("    !p\n    !l\n    !s")
    
    output.append("    EXPAND NODE_OS_PLATFORM p, l, s")
    output.append("    !p\n    !l\n    !s")
    
    output.append("    return 0")
        
    with open("tests/node_plugin_unit_test.sa", "w") as f:
        f.write("\n".join(output))

if __name__ == "__main__":
    recover_test()
