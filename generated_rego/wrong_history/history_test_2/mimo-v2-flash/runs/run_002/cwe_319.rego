package glitch

import data.glitch_lib

insecure_url_pattern = `(?i)^(http://|ftp://|telnet://|smtp://|ldap://)`
insecure_protocols = {"http", "ftp", "telnet", "smtp", "ldap"}
insecure_attributes = {"validate_certs", "ssl_enabled", "use_ssl", "force_https", "secure_connection", "enforce_ssl"}
insecure_boolean_values = {false, "no"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check atomic units (Ansible tasks, Chef resources, etc.)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check attributes of atomic units for insecure URLs
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name suggests URL transmission
    url_attr_names = {"source", "url", "dest", "path", "base_url", "grafana_url"}
    attr.name_lower := lower(attr.name)
    url_attr_names[_] == attr.name_lower
    
    # Check value for insecure URL pattern
    glitch_lib.traverse(attr.value, insecure_url_pattern)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Use of unencrypted protocols for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check atomic units for insecure flags
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name is in insecure attributes list
    attr.name_lower := lower(attr.name)
    insecure_attributes[_] == attr.name_lower
    
    # Check if value is insecure (false or "no")
    check_insecure_value(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure flag disables encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for insecure URLs
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check variable value for insecure URL pattern
    glitch_lib.traverse(var.value, insecure_url_pattern)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable contains insecure URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for insecure protocol settings in hashes
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if variable value is a hash
    var.value.ir_type == "Hash"
    
    # Get key-value pairs from hash
    hash_pairs := var.value.value
    pair := hash_pairs[_]
    
    # Check for insecure protocol setting
    pair.key.ir_type == "String"
    lower(pair.key.value) == "protocol"
    
    pair.value.ir_type == "String"
    insecure_protocols[_] == lower(pair.value.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash contains insecure protocol setting. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for insecure boolean settings in hashes
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if variable value is a hash
    var.value.ir_type == "Hash"
    
    # Get key-value pairs from hash
    hash_pairs := var.value.value
    pair := hash_pairs[_]
    
    # Check for insecure boolean setting
    pair.key.ir_type == "String"
    lower(pair.key.value) == insecure_attributes[_]
    
    check_insecure_value(pair.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash contains insecure setting. (CWE-319)"
    }
}

check_insecure_value(value) {
    value.ir_type == "Boolean"
    insecure_boolean_values[_] == value.value
} else {
    value.ir_type == "String"
    insecure_boolean_values[_] == value.value
}