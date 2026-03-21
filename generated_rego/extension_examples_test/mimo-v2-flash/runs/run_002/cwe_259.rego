package glitch

import data.glitch_lib

sensitive_keywords = {"password", "pass", "pwd", "secret", "token", "credential", "key", "api_key", "access_key", "secret_key"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "String"
    contains_key := sensitive_keywords[_]
    contains(var.name, contains_key)
    not path_like(var.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded secret in variable"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.value.ir_type == "String"
    contains_key := sensitive_keywords[_]
    contains(attr.name, contains_key)
    not path_like(attr.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded secret in attribute"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some i
    key_value := node.value[i]
    key_value.key.ir_type == "String"
    contains_key := sensitive_keywords[_]
    contains(key_value.key.value, contains_key)
    key_value.value.ir_type == "String"
    not path_like(key_value.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": key_value.key,
        "path": parent.path,
        "description": "Hard-coded secret in hash key-value pair"
    }
}

path_like(s) {
    regex.match(".*[/\\\\].*", s)
}