package glitch

import data.glitch_lib

# Helper rule to check if a key is IP-related
key_is_ip_related(key) {
    key.ir_type == "VariableReference"
    regex.match("(?i)(ip|address|bind|host|addr|bind-address|bind_address)", key.value)
} else {
    key.ir_type == "String"
    regex.match("(?i)(ip|address|bind|host|addr|bind-address|bind_address)", key.value)
}

# Recursive rule to check if a Hash contains "0.0.0.0" under an IP-related key
check_hash_for_public_ip(hash) {
    hash.ir_type == "Hash"
    kv := hash.value[_]
    key_is_ip_related(kv.key)
    kv.value.ir_type == "String"
    kv.value.value == "0.0.0.0"
} else {
    hash.ir_type == "Hash"
    kv := hash.value[_]
    kv.value.ir_type == "Hash"
    check_hash_for_public_ip(kv.value)
}

# Rule to check if a value has public IP (0.0.0.0)
has_public_ip(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0"
} else {
    value.ir_type == "Hash"
    check_hash_for_public_ip(value)
}

# Main detection rule for CWE-284
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables
    var := glitch_lib.all_variables(parent)
    var.name != ""
    regex.match("(?i)(ip|address|bind|host|addr|bind-address|bind_address)", var.name)
    has_public_ip(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes
    attr := glitch_lib.all_attributes(parent)
    attr.name != ""
    regex.match("(?i)(ip|address|bind|host|addr|bind-address|bind_address)", attr.name)
    has_public_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to all interfaces (0.0.0.0). (CWE-284)"
    }
}