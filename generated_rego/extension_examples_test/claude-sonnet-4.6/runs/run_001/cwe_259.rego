package glitch

import data.glitch_lib

is_password_field(name) {
    regex.match("(?i)(password|passwd|pwd)", name)
}

is_dynamic_reference(str) {
    regex.match("(?i)(\\$\\{|\\$\\(|\\{\\{|var\\.|data\\.|local\\.|ssm:|arn:|vault:)", str)
}

is_env_password_string(str) {
    regex.match("(?i).*(_PASSWORD|_PASSWD|_PWD|_PASS)=.+", str)
    not is_dynamic_reference(str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, v])
    v.ir_type == "Variable"
    v.value.ir_type == "String"
    v.value.value != ""
    is_password_field(v.name)
    not is_dynamic_reference(v.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password in variable - Password fields should not contain literal string values. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    attr.value.ir_type == "String"
    attr.value.value != ""
    is_password_field(attr.name)
    not is_dynamic_reference(attr.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password in attribute - Password fields should not contain literal string values. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_password_field(entry.key.value)
    entry.value.ir_type == "String"
    entry.value.value != ""
    not is_dynamic_reference(entry.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password in nested structure - Password fields should not contain literal string values. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, str_node])
    str_node.ir_type == "String"
    is_env_password_string(str_node.value)
    result := {
        "type": "sec_hard_pass",
        "element": str_node,
        "path": parent.path,
        "description": "Use of hard-coded password in environment variable string - Credentials should not be embedded as literal strings. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    method_entry := hash_node.value[_]
    method_entry.key.ir_type == "String"
    method_entry.key.value == "method"
    method_entry.value.ir_type == "String"
    regex.match("(?i)^key$", method_entry.value.value)
    key_entry := hash_node.value[_]
    key_entry.key.ir_type == "String"
    key_entry.key.value == "key"
    key_entry.value.ir_type == "String"
    key_entry.value.value != ""
    not is_dynamic_reference(key_entry.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": key_entry.value,
        "path": parent.path,
        "description": "Use of hard-coded authentication key - Auth keys should not be stored as literal string values. (CWE-259)"
    }
}