package glitch

import data.glitch_lib

sensitive_keywords := {"password", "secret", "api_key", "token", "credential", "auth", "passwd", "key"}

is_non_secret_string(value) {
    value == "localhost"
} else {
    value == "0.0.0.0"
} else {
    value == "true"
} else {
    value == "false"
} else {
    value == "nil"
} else {
    value == "null"
} else {
    regex.match(`^\d+$`, value)
} else {
    regex.match(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, value)
} else {
    contains(value, "/")
} else {
    contains(value, ".")
} else {
    regex.match(`^[A-Za-z0-9_-]+$`, value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    hash_entry := node.value[_]
    key := hash_entry.key
    value := hash_entry.value
    
    key.ir_type == "String"
    key_name_lower := lower(key.value)
    keyword := sensitive_keywords[_]
    contains(key_name_lower, keyword)
    
    value.ir_type == "String"
    value.value != ""
    not is_non_secret_string(value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": value,
        "path": parent.path,
        "description": "Hard-coded password in nested configuration - Avoid using hard-coded passwords. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    variable_name_lower := lower(variable.name)
    keyword := sensitive_keywords[_]
    contains(variable_name_lower, keyword)
    
    variable.value.ir_type == "String"
    variable.value.value != ""
    not is_non_secret_string(variable.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Hard-coded password in variable - Avoid using hard-coded passwords. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr_name_lower := lower(attr.name)
    keyword := sensitive_keywords[_]
    contains(attr_name_lower, keyword)
    
    attr.value.ir_type == "String"
    attr.value.value != ""
    not is_non_secret_string(attr.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in attribute - Avoid using hard-coded passwords. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr_name_lower := lower(attr.name)
    keyword := sensitive_keywords[_]
    contains(attr_name_lower, keyword)
    
    attr.value.ir_type == "String"
    attr.value.value != ""
    not is_non_secret_string(attr.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in attribute - Avoid using hard-coded passwords. (CWE-259)"
    }
}