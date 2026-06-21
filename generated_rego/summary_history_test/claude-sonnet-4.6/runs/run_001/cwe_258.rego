package glitch

import data.glitch_lib

is_password_field(name) {
    regex.match("(?i).*(password|passwd|pwd|passphrase|credential|activationkey|activation_key).*", name)
}

is_password_field(name) {
    regex.match("(?i).*secret$", name)
}

is_password_field_strict(name) {
    regex.match("(?i)(password|passwd|pwd|passphrase)([^a-z0-9_].*|$)", name)
}

is_password_field_strict(name) {
    regex.match("(?i).*[^a-z0-9_](password|passwd|pwd|passphrase)([^a-z0-9_].*|$)", name)
}

is_empty_string(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field(v.name)
    is_empty_string(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or whitespace-only values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field_strict(v.name)
    v.value.ir_type == "Null"
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or whitespace-only values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field(v.name)
    v.value.ir_type == "Undef"
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or whitespace-only values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or whitespace-only values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    attr.value.ir_type == "Null"
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or whitespace-only values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    attr.value.ir_type == "Undef"
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or whitespace-only values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    regex.match(sprintf("(?i)\\$%s\\s*=\\s*['\"]\\s*['\"]", [arg.value]), parent.code)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password-related fields should not be assigned empty or whitespace-only values. (CWE-258)"
    }
}