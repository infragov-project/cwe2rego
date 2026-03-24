package glitch

import data.glitch_lib

insecure_protocols = {"http", "ftp", "telnet"}
insecure_values = {"false", "disabled", "none", "no", "disable", "0"}
insecure_keys = {
    "protocol", "ssl", "tls", "encryption", 
    "enable_https_traffic_only", "require_ssl", "enforce_tls", "secure_transfer",
    "validate_certs", "ssl_mode", "start_tls", "ssl_skip_verify"
}

is_insecure_string_value(value) {
    value.ir_type == "String"
    value.value in insecure_values
} else {
    value.ir_type == "Boolean"
    value.value == false
}

is_insecure_key_value(key, value) {
    key in insecure_keys
    is_insecure_string_value(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_insecure_key_value(attr.name, attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure encryption setting found. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables with insecure key-value pairs in hashes
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    
    kv.key.ir_type == "String"
    kv.value.ir_type == "String"
    
    is_insecure_key_value(kv.key.value, kv.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure setting in variable hash. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for insecure protocols in strings (URLs)
    walk(parent, [path, node])
    node.ir_type == "String"
    
    # Match strings that start with insecure protocols
    regex.match("^(http|ftp|telnet)://", node.value)
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol in URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for hardcoded secrets in URLs
    walk(parent, [path, node])
    node.ir_type == "String"
    
    # Match patterns like http://user:password@host
    regex.match("^(http|ftp|telnet)://[^:]+:[^@]+@", node.value)
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Hardcoded secret in URL. (CWE-319)"
    }
}