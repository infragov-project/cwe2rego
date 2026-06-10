package glitch

import data.glitch_lib

unencrypted_protocols = {"http", "ftp", "telnet", "smtp"}
unencrypted_ports = {80, 21, 23, 25}
encryption_flags = {"ssl_enabled", "enable_ssl", "use_tls", "require_encryption", "encrypt", "force_ssl", "enable_https_only", "validate_certs"}

check_unencrypted_url(value) {
    value.ir_type == "String"
    regex.match("^(http|ftp|telnet|smtp)://", value.value)
}

check_unencrypted_protocol(value) {
    value.ir_type == "String"
    value.value in unencrypted_protocols
}

check_unencrypted_port(value) {
    value.ir_type == "Integer"
    value.value in unencrypted_ports
} else {
    value.ir_type == "String"
    port_num := to_number(value.value)
    port_num in unencrypted_ports
}

check_encryption_flag(name, value) {
    name in encryption_flags
    value.ir_type == "Boolean"
    value.value == false
} else {
    name in encryption_flags
    value.ir_type == "String"
    value.value == "no"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check AtomicUnits and their attributes
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Get all attributes including nested ones
    all_attrs := glitch_lib.all_attributes(node)
    attr := all_attrs[_]
    
    # Check for unencrypted URLs in attribute values
    check_unencrypted_url(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted URL found. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check AtomicUnits and their attributes
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    all_attrs := glitch_lib.all_attributes(node)
    attr := all_attrs[_]
    
    # Check for unencrypted protocol
    attr.name == "protocol"
    check_unencrypted_protocol(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check AtomicUnits and their attributes
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    all_attrs := glitch_lib.all_attributes(node)
    attr := all_attrs[_]
    
    # Check for unencrypted ports
    attr.name == "port"
    check_unencrypted_port(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted port used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check AtomicUnits and their attributes
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    all_attrs := glitch_lib.all_attributes(node)
    attr := all_attrs[_]
    
    # Check for encryption flags set to false/no
    check_encryption_flag(attr.name, attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # For variables with Hash values, check their key-value pairs
    var.value.ir_type == "Hash"
    hash_value := var.value.value
    
    # Iterate through hash key-value pairs
    some kv in hash_value
    attr_name := kv.key.value
    attr_value := kv.value
    
    # Check for unencrypted URLs in variable values
    check_unencrypted_url(attr_value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted URL in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # For variables with Hash values, check their key-value pairs
    var.value.ir_type == "Hash"
    hash_value := var.value.value
    
    # Iterate through hash key-value pairs
    some kv in hash_value
    attr_name := kv.key.value
    attr_value := kv.value
    
    # Check for unencrypted protocol in variable hash
    attr_name == "protocol"
    check_unencrypted_protocol(attr_value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # For variables with Hash values, check their key-value pairs
    var.value.ir_type == "Hash"
    hash_value := var.value.value
    
    # Iterate through hash key-value pairs
    some kv in hash_value
    attr_name := kv.key.value
    attr_value := kv.value
    
    # Check for encryption flags in variable hash
    check_encryption_flag(attr_name, attr_value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption disabled in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables with String values that contain URLs
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if variable value is a String
    var.value.ir_type == "String"
    check_unencrypted_url(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted URL in string variable. (CWE-319)"
    }
}