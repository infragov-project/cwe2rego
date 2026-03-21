package glitch

import data.glitch_lib

sensitive_name_keywords := {"password", "pwd", "pass", "secret", "key", "token", "credential", "auth", "passphrase"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    glitch_lib.contains(var.name, sensitive_name_keywords[_])
    var.value.ir_type == "String"
    var.value.value != ""
    not is_file_path(var.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded password in variable. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    glitch_lib.contains(attr.name, sensitive_name_keywords[_])
    attr.value.ir_type == "String"
    attr.value.value != ""
    not is_file_path(attr.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in attribute. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    not is_file_path(node.value)
    count(path) > 0
    key := path[count(path) - 1]
    is_string(key)
    glitch_lib.contains(key, sensitive_name_keywords[_])
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password in nested structure. (CWE-259)"
    }
}

is_file_path(str) {
    regex.match("^[a-zA-Z]:\\\\", str)
}

is_file_path(str) {
    regex.match("^/", str)
}

is_file_path(str) {
    regex.match("^\\./", str)
}

is_file_path(str) {
    regex.match("^[a-zA-Z]:/", str)
}