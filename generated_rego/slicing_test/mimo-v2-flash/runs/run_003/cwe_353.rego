package glitch

import data.glitch_lib

# Insecure protocols that lack integrity checks
insecure_protocols := {"http://", "ftp://", "telnet://", "smtp://", "pptp://"}

# Insecure attributes that disable integrity checks
insecure_attributes := {
    "validate_certs": {"no", false},
    "gpgcheck": {0, false},
    "ssl": {false, "disabled", "no"},
    "tls_version": {"none", "disabled"},
    "encryption": {false, "disabled", "no"},
    "integrity_check": {false, "disabled", "no"},
    "checksum_verification": {false, "disabled", "no"},
    "signing_algorithm": {"none", "disabled"},
    "allow_plaintext": {true, "yes"},
}

# Helper to check if a string value contains an insecure protocol
check_insecure_protocol_string(value) {
    value.ir_type == "String"
    some protocol
    insecure_protocols[protocol]
    startswith(lower(value.value), protocol)
}

# Helper to check if a complex value contains an insecure protocol (recursive)
check_insecure_protocol_complex(value) {
    walk(value, [path, node])
    node.ir_type == "String"
    check_insecure_protocol_string(node)
}

# Check if an attribute has insecure settings
check_insecure_attribute(attr) {
    insecure_attributes[attr.name]
    attr.value.ir_type == "String"
    some insecure_val
    insecure_attributes[attr.name][insecure_val]
    lower(attr.value.value) == lower(insecure_val)
} else {
    insecure_attributes[attr.name]
    attr.value.ir_type == "Boolean"
    some insecure_val
    insecure_attributes[attr.name][insecure_val]
    attr.value.value == insecure_val
} else {
    insecure_attributes[attr.name]
    attr.value.ir_type == "Integer"
    some insecure_val
    insecure_attributes[attr.name][insecure_val]
    attr.value.value == insecure_val
} else {
    attr.name == "source"
    check_insecure_protocol_complex(attr.value)
}

# Rule 1: Check atomic units for insecure attributes (like validate_certs: no)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    check_insecure_attribute(attr)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,  # Return the atomic unit, not the attribute
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure attribute setting (CWE-353)"
    }
}

# Rule 2: Check atomic units for insecure protocols in source URLs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "source"
    check_insecure_protocol_complex(attr.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,  # Return the atomic unit
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure protocol in source URL (CWE-353)"
    }
}

# Rule 3: Check variables for insecure settings in Hash values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var_node := variables[_]
    var_node.value.ir_type == "Hash"
    
    walk(var_node.value, [path, node])
    node.ir_type == "Attribute"
    check_insecure_attribute(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": var_node,  # Return the variable, not the nested attribute
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure setting in variable (CWE-353)"
    }
}

# Rule 4: Check variables for insecure settings in Array values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var_node := variables[_]
    var_node.value.ir_type == "Array"
    
    walk(var_node.value, [path, node])
    node.ir_type == "Attribute"
    check_insecure_attribute(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": var_node,  # Return the variable
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure setting in variable (CWE-353)"
    }
}

# Rule 5: Check variables for insecure protocols in Hash values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var_node := variables[_]
    var_node.value.ir_type == "Hash"
    
    walk(var_node.value, [path, node])
    node.ir_type == "String"
    check_insecure_protocol_string(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": var_node,  # Return the variable
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure protocol in variable (CWE-353)"
    }
}

# Rule 6: Check variables for insecure protocols in Array values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var_node := variables[_]
    var_node.value.ir_type == "Array"
    
    walk(var_node.value, [path, node])
    node.ir_type == "String"
    check_insecure_protocol_string(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": var_node,  # Return the variable
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure protocol in variable (CWE-353)"
    }
}