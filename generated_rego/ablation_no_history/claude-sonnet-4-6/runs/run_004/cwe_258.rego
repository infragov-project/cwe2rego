package glitch

import data.glitch_lib

is_password_related(name) {
    regex.match("(?i).*(password|passwd|pwd|pass|secret|credential|auth_pass|auth_token).*", name)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "String"
    regex.match("^\\s+$", value.value)
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_related(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    is_password_related(variable.name)
    is_empty_value(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related variables should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_related(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    all_parent_attrs := glitch_lib.all_attributes(parent)
    ref_attr := all_parent_attrs[_]
    ref_attr.name == var_name
    is_empty_value(ref_attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password-related fields reference empty password variables. (CWE-258)"
    }
}