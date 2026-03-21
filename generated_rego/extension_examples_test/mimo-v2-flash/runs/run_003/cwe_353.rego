package glitch

import data.glitch_lib

# Insecure protocol patterns based on CWE-353
insecure_protocol_patterns := {
    "http",
    "ftp",
    "smtp",
    "plain",
    "sasl_plaintext",
    "plaintext"
}

# Check if a string contains an insecure protocol
contains_insecure_protocol(str) {
    regex.match(sprintf("(?i).*\\b(%s)\\b.*", [concat("|", insecure_protocol_patterns)]), str)
}

# Check for insecure boolean flags
insecure_boolean_flags := {
    "encryption": false,
    "enable_encryption": false,
    "ssl": false,
    "tls_enabled": false,
    "secure_transfer": false,
    "disable_encryption": true,
    "https_only": false,
    "redirect_http_to_https": false,
    "require_ssl": false,
    "ipsec_encryption": false,
    "enable_perfect_forward_secrecy": false,
    "checksum": false,
    "enable_checksum": false
}

# Check for insecure string values
insecure_string_values := {
    "tls_version": "tlsv1",
    "min_tls_version": "none",
    "ssl_policy": "legacy",
    "ssl_mode": "disabled",
    "api_gateway_protocol": "HTTP",
    "function_trigger": "http",
    "integrity_algorithm": "none",
    "data_validation": "none"
}

# Check if attribute matches insecure patterns
check_insecure_attribute(attr) {
    # Check for insecure protocol in string values
    attr.value.ir_type == "String"
    contains_insecure_protocol(attr.value.value)
} else {
    # Check for insecure boolean flags
    attr.value.ir_type == "Boolean"
    insecure_boolean_flags[attr.name] == attr.value.value
} else {
    # Check for insecure string values
    attr.value.ir_type == "String"
    insecure_string_values[attr.name] == attr.value.value
}

# Check for insecure URLs in attributes
check_insecure_url(attr) {
    attr.value.ir_type == "String"
    regex.match("(?i)^https?://", attr.value.value)
    not regex.match("(?i)^https://", attr.value.value)
}

# Check for insecure URLs in complex values (like Sum/concatenation)
check_insecure_url_complex(value) {
    walk(value, [path, node])
    node.ir_type == "String"
    regex.match("(?i)^https?://", node.value)
    not regex.match("(?i)^https://", node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure attributes
    check_insecure_attribute(attr)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - The configuration does not support integrity checks for data in transit. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure URLs in attributes
    check_insecure_url(attr)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - The configuration uses insecure protocol (HTTP) for data transmission. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure URLs in complex values (like Sum/concatenation)
    attr.value.ir_type != "String"
    check_insecure_url_complex(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - The configuration uses insecure protocol (HTTP) for data transmission. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    # Check variables for insecure URL assignments
    node.value.ir_type == "String"
    check_insecure_url({"value": node.value})
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Variable uses insecure protocol (HTTP) for data transmission. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    # Check variables with Hash values for insecure URLs
    node.value.ir_type == "Hash"
    walk(node.value, [path, leaf])
    leaf.ir_type == "String"
    check_insecure_url({"value": leaf})
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Configuration contains insecure protocol (HTTP) in variable definitions. (CWE-353)"
    }
}