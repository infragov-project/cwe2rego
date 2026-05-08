package glitch

import data.glitch_lib

password_keywords := {"password", "pass", "pwd", "secret", "token", "key", "credential", "auth", "passphrase"}

is_password_name(name) {
    lower_name := lower(name)
    keyword := password_keywords[_]
    contains(lower_name, keyword)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_name(var.name)
    is_empty_value(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in variable - Passwords or secrets should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_password_name(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in attribute - Passwords or secrets should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    is_password_name(pair.key.value)
    is_empty_value(pair.value)
    result := {
        "type": "sec_empty_pass",
        "element": pair,
        "path": parent.path,
        "description": "Empty password in configuration hash - Passwords or secrets should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    walk(attr.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    is_password_name(pair.key.value)
    is_empty_value(pair.value)
    result := {
        "type": "sec_empty_pass",
        "element": pair,
        "path": parent.path,
        "description": "Empty password in configuration hash - Passwords or secrets should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match("(?i)(password|pass|pwd|secret|token|key|credential|auth|passphrase)=[;,]", node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in connection string - Connection strings should not contain empty password values. (CWE-258)"
    }
}