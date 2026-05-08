package glitch

import data.glitch_lib

# Check for insecure URL patterns in String values
is_insecure_url(str_value) {
    regex.match("(?i)^(http://|ftp://)", str_value)
}

# Check for insecure protocol names
is_insecure_protocol(str_value) {
    regex.match("(?i)^(http|ftp|tcp|udp)$", str_value)
}

# Check for insecure port numbers
is_insecure_port(port_value) {
    port_value == 80
} else {
    port_value == 21
} else {
    port_value == 23
}

# Check if node represents insecure configuration
check_node_insecure(node) {
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    node.name in {"url", "source", "baseurl", "mirrorlist", "endpoint"}
    is_insecure_url(node.value.value)
} else {
    node.ir_type == "Attribute"
    node.value.ir_type == "Boolean"
    node.name in {"use_tls", "ssl_enabled", "validate_certs"}
    node.value.value == false
} else {
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    node.name == "encryption"
    node.value.value == "none"
} else {
    node.ir_type == "Attribute"
    node.value.ir_type == "Integer"
    node.name == "port"
    is_insecure_port(node.value.value)
} else {
    node.ir_type == "Attribute"
    node.value.ir_type == "Integer"
    node.name in {"validate_certs", "gpgcheck"}
    node.value.value == 0
} else {
    node.ir_type == "Attribute"
    node.value.ir_type == "Null"
    node.name in {"validate_integrity", "integrity_check", "verify_hash", "checksum"}
} else {
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    node.name in {"epel_mirror_baseurl"}
    is_insecure_url(node.value.value)
}

# Check Hash values for insecure configurations
check_hash_insecure(hash_values) {
    kv := hash_values[_]
    key := kv.key
    value := kv.value
    
    key.ir_type == "String"
    key.value in {"url", "source", "baseurl", "mirrorlist"}
    value.ir_type == "String"
    is_insecure_url(value.value)
} else {
    kv := hash_values[_]
    value := kv.value
    
    value.ir_type == "Hash"
    check_hash_insecure(value.value)
} else {
    kv := hash_values[_]
    key := kv.key
    value := kv.value
    
    key.ir_type == "String"
    key.value in {"use_tls", "ssl_enabled", "encryption"}
    value.ir_type == "Boolean"
    value.value == false
}

# Main rule to detect CWE-353
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all atomic units and check them
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    check_node_insecure(attr)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "CWE-353: Insecure transmission protocol or URL detected (missing integrity checks)"
    }
}

# Check variables in unit blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables defined in the unit block
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    
    check_node_insecure(variable)
    
    result := {
        "type": "sec_no_int_check",
        "element": variable,
        "path": parent.path,
        "description": "CWE-353: Insecure transmission protocol or URL detected in variables (missing integrity checks)"
    }
}

# Check Hash attributes for insecure configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    # Check if attribute value is a Hash
    attr.value.ir_type == "Hash"
    check_hash_insecure(attr.value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "CWE-353: Insecure transmission protocol or URL detected in hash configuration (missing integrity checks)"
    }
}