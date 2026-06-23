package glitch

import data.glitch_lib

import future.keywords.in

credential_patterns := {"password", "passwd", "pwd", "secret", "token", "credential", "key", "auth"}
weak_passwords := {"admin", "password", "123456", "default", "secret", "root", "changeme", "todo", "fixme", "test", "pass", "pass123", "welcome", "guest", "user", "login", "admin123"}

is_password_field(name) {
    lower_name := lower(name)
    pattern := credential_patterns[_]
    regex.match(sprintf(".*%s.*", [pattern]), lower_name)
}

is_weak_password(value) {
    lower_val := lower(value)
    weak_passwords[lower_val]
}

is_literal_string(value) {
    value.ir_type == "String"
    not regex.match("\\$\\{|\\{\\{|\\$\\(", value.value)
}

has_password_in_name(varname) {
    parts := split(varname, ".")
    some part in parts
    is_password_field(part)
}

# Helper to extract all key-value pairs from deeply nested structures
extract_key_values(node) = kvs {
    walk(node, [path, val])
    val.ir_type == "Hash"
    e := val.value[_]
    e.key.ir_type == "String"
    kvs := {"key": e.key.value, "value": e.value, "key_element": e.key, "val_element": e.value}
}

# Check if a string contains password pattern like KEY=password
contains_password_pattern(str) {
    regex.match("^[A-Z_]*PASSWORD[A-Z_]*=", upper(str))
    not regex.match("\\$\\{|\\{\\{|\\$\\(", str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables at any nested level
    vars := {v | walk(parent, [_, v]); v.ir_type == "Variable"}
    var := vars[_]
    
    kv := extract_key_values(var.value)[_]
    is_password_field(kv.key)
    v := kv.value
    
    v.ir_type == "String"
    is_literal_string(v)
    
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes at any nested level
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    
    kv := extract_key_values(attr.value)[_]
    is_password_field(kv.key)
    v := kv.value
    
    v.ir_type == "String"
    is_literal_string(v)
    
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attribute names directly
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    
    is_password_field(attr.name)
    attr.value.ir_type == "String"
    is_literal_string(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variable names directly
    walk(parent, [_, var])
    var.ir_type == "Variable"
    
    has_password_in_name(var.name)
    var.value.ir_type == "String"
    is_literal_string(var.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for passwords embedded in string array elements like ENV_VAR=value
    walk(parent, [_, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "String"
    contains_password_pattern(elem.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": elem,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded in configuration files. Use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    kv := extract_key_values(parent)[_]
    is_password_field(kv.key)
    v := kv.value
    
    v.ir_type == "String"
    is_weak_password(v.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password - Weak or default password detected. Use secret management systems instead. (CWE-259)"
    }
}