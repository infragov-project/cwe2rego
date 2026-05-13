package glitch

import data.glitch_lib

# Detect insecure transport protocols (CWE-353)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    regex.match("^(http://|ftp://)", attr.value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure transport protocol detected. (CWE-353)"
    }
}

# Detect disabled certificate/validation checks (CWE-353)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    validation_names := {"validate_certs", "gpgcheck", "sslverify", "verify", "repo_gpgcheck"}
    validation_names[attr.name]
    
    attr.value.ir_type == "String"
    disabled_values := {"no", "false", "disabled", "0"}
    attr.value.value in disabled_values
    
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Certificate/validation disabled. (CWE-353)"
    }
}

# Detect insecure protocols in variables (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "String"
    regex.match("^(http://|ftp://)", var.value.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Variable contains insecure transport protocol. (CWE-353)"
    }
}

# Detect insecure protocols in Hash values (nested configurations)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    walk(node, [hash_path, value_node])
    value_node.ir_type == "String"
    regex.match("^(http://|ftp://)", value_node.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": value_node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Insecure transport protocol in configuration. (CWE-353)"
    }
}

# Detect disabled integrity features in Hash values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    walk(node, [hash_path, key_node])
    key_node.ir_type == "String"
    key_node.value in {"gpgcheck", "repo_gpgcheck", "sslverify"}
    
    walk(node, [hash_path, value_node])
    value_node.ir_type == "String"
    value_node.value in {"0", "no", "false"}
    
    result := {
        "type": "sec_no_int_check",
        "element": value_node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity check disabled in configuration. (CWE-353)"
    }
}