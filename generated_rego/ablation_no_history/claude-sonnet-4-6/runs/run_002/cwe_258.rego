package glitch

import data.glitch_lib

password_pattern := "(?i).*(password|passwd|passphrase|pwd|pass_|_pass|credential|auth_token|secret|_key|activationkey|secretkey|api_key|auth_key).*"

is_empty_string(value) {
    value.ir_type == "String"
    value.value == ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_pattern, attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Authentication fields should not have empty passwords. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    regex.match(password_pattern, variable.name)
    is_empty_string(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration - Authentication fields should not have empty passwords. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_pattern, attr.name)
    walk(attr.value, [_, ref])
    ref.ir_type == "VariableReference"
    var_name := ref.value
    context_attrs := glitch_lib.all_attributes(parent)
    ref_attr := context_attrs[_]
    ref_attr.name == var_name
    is_empty_string(ref_attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Authentication fields should not have empty passwords. (CWE-258)"
    }
}