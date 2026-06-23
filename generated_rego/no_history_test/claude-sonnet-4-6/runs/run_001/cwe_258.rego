package glitch

import data.glitch_lib

is_sensitive_name(name) {
    regex.match(`(?i).*(password|passwd|pwd|passphrase|credential|auth_?key|bind_password|ldap_password|activation_?key)`, name)
}

is_sensitive_name(name) {
    regex.match(`(?i).*secret$`, name)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_name(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_sensitive_name(v.name)
    is_empty_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be set to empty or null values. (CWE-258)"
    }
}