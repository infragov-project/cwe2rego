package glitch

import data.glitch_lib

is_password_field(name) {
    regex.match(`(?i).*(password|passwd|secret|credential|auth_token|access_key|api_key).*`, name)
}

is_password_field(name) {
    regex.match(`(?i)^(pass|pwd)$`, name)
}

is_password_field(name) {
    regex.match(`(?i).*(_pass|_pwd|_secret|_token|_credential|_key)$`, name)
}

is_empty_value(value) {
    value.ir_type == "String"
    regex.match(`^\s*$`, value.value)
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields must not be set to an empty, null, or whitespace-only value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field(v.name)
    is_empty_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields must not be set to an empty, null, or whitespace-only value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    is_password_field(pair.key.value)
    is_empty_value(pair.value)
    result := {
        "type": "sec_empty_pass",
        "element": pair.key,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields must not be set to an empty, null, or whitespace-only value. (CWE-258)"
    }
}