package glitch

import data.glitch_lib

# Helper functions to detect insecure values
insecure_boolean(value) {
    value.ir_type == "Boolean"
    value.value == false
}

insecure_integer(value) {
    value.ir_type == "Integer"
    value.value == 0
}

insecure_string(value) {
    value.ir_type == "String"
    regex.match("(?i)^(no|false|disabled|0)$", value.value)
}

# Rule 1: Check for insecure attributes in AtomicUnits (like validate_certs: no)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure attributes in various IaC technologies
    attr.name in {"validate_certs", "ssl_verify", "tls_verify", "gpgcheck", "signature_check"}
    (insecure_boolean(attr.value) or insecure_integer(attr.value) or insecure_string(attr.value))
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure integrity check setting (CWE-353)"
    }
}

# Rule 2: Check for insecure protocols in URL attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check URL attributes for insecure protocols
    attr.name in {"url", "source", "baseurl", "mirrorlist"}
    attr.value.ir_type == "String"
    regex.match("(?i)^http://", attr.value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure HTTP protocol used for data transmission (CWE-353)"
    }
}

# Rule 3: Check for insecure protocols in Hash/Variable values (like in yum repos)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if the variable value is a Hash
    var.value.ir_type == "Hash"
    
    # Walk through the hash to find insecure attributes
    walk(var.value, [path, node])
    node.ir_type == "KeyValue"
    node.name in {"gpgcheck", "ssl_verify", "validate_certs"}
    (insecure_boolean(node.value) or insecure_integer(node.value) or insecure_string(node.value))
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Insecure integrity check in repository configuration (CWE-353)"
    }
}

# Rule 4: Check for insecure protocols in code strings (like in Chef remote_file)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for insecure protocols in the code string
    node.code != ""
    regex.match("(?i)http://", node.code)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Insecure HTTP protocol in code (CWE-353)"
    }
}

# Rule 5: Check for missing integrity checks in file transfer resources
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for file transfer resource types
    node.type in {"get_url", "remote_file", "fetch", "s3", "azure_blob"}
    
    # Check if there's no checksum/hash attribute
    attrs := glitch_lib.all_attributes(node)
    has_checksum := false
    some attr in attrs
    attr.name in {"checksum", "hash", "integrity_check", "validate"}
    has_checksum := true
    
    not has_checksum
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check in file transfer resource (CWE-353)"
    }
}