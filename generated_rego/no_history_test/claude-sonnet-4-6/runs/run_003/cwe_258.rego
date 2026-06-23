package glitch

import data.glitch_lib

is_password_attr(name) {
    regex.match(`(?i)(password|passwd|passphrase|pwd|credential)`, name)
}

is_password_attr(name) {
    regex.match(`(?i)secret`, name)
    not regex.match(`(?i)secret_key`, name)
    not regex.match(`(?i)access_key`, name)
}

is_empty_string_value(value) {
    value.ir_type == "String"
    regex.match(`^\s*$`, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_attr(attr.name)
    is_empty_string_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields should not be set to empty or blank values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_attr(v.name)
    is_empty_string_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields should not be set to empty or blank values. (CWE-258)"
    }
}