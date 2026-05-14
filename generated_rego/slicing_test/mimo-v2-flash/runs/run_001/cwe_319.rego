package glitch

import data.glitch_lib

# Generalized check for insecure protocols (http, ftp, etc.) in string values
check_insecure_protocol(str_val) {
    insecure_protocols := {"http://", "ftp://", "telnet://", "smtp://"}
    startswith(str_val, insecure_protocols[_])
}

# Check for insecure encryption flags set to false/disabled
check_insecure_encryption_flag(attr_name, attr_value) {
    insecure_flags := {
        "validate_certs": {"no", "false"},
        "ssl_verify": {"no", "false"},
        "tls": {"disabled", "false"},
        "ssl": {"disabled", "false"},
        "enforce_https": {"false"},
        "enable_https_traffic_only": {"false"}
    }
    attr_value.ir_type == "String"
    attr_name == key
    insecure_flags[key][_] == attr_value.value
}

# Detect insecure protocol in Hash values within Variables (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]

    # Traverse the hash structure to find key-value pairs
    var.value.ir_type == "Hash"
    walk(var.value, [path, n])
    n.ir_type == "String"
    
    # Check if we are at a key-value pair in the hash
    # The walk path will contain the key and value objects
    # We need to find the key "protocol" with value "http"
    path_count := count(path)
    path_count > 0
    last_path_element := path[path_count - 1]
    last_path_element == "key" or last_path_element == "value"
    
    # Get the parent object to access both key and value
    parent_obj := var.value
    for i := 1; i < count(path) - 1; i++ {
        parent_obj := parent_obj[path[i]]
    }
    
    # Check if this is the "protocol" key with insecure value
    parent_obj.key.ir_type == "String"
    parent_obj.key.value == "protocol"
    parent_obj.value.ir_type == "String"
    parent_obj.value.value == "http"

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in configuration hash. (CWE-319)"
    }
}

# Detect insecure protocol directly in Hash key-value pairs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]

    var.value.ir_type == "Hash"
    hash_entries := var.value.value
    
    # Iterate through hash entries directly
    entry := hash_entries[_]
    entry.key.ir_type == "String"
    entry.key.value == "protocol"
    entry.value.ir_type == "String"
    entry.value.value == "http"

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in configuration hash. (CWE-319)"
    }
}