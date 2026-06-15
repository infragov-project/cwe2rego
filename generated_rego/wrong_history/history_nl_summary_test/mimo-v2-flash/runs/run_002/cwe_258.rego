package glitch

import data.glitch_lib
import future.keywords.in

is_password_related(name) {
    regex.match("(?i)(password|pwd|passphrase|key|secret|auth|credential|token)", name)
}

check_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_empty_variable_ref(ref, parent) {
    ref.ir_type == "VariableReference"
    var_name := ref.value
    some var in glitch_lib.all_variables(parent)
    var.name == var_name
    check_empty_password(var.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    is_password_related(var.name)
    check_empty_password(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in variable assignment - Password variables should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    is_password_related(attr.name)
    check_empty_password(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be left empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    functions := {n |
        walk(parent, [path, n])
        n.ir_type == "FunctionCall"
        regex.match("(?i)(password|crypt|hash|encrypt)", n.name)
        count(n.args) > 0
        arg := n.args[_]
        check_empty_password(arg) or (arg.ir_type == "VariableReference" and is_empty_variable_ref(arg, parent))
    }
    func := functions[_]
    result := {
        "type": "sec_empty_pass",
        "element": func,
        "path": parent.path,
        "description": "Empty password passed to password function - Password functions should not receive empty values. (CWE-258)"
    }
}