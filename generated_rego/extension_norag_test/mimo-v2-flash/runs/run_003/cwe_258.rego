package glitch

import data.glitch_lib

password_pattern := "(?i)(password|passwd|pwd|passphrase|key|token|secret|credential|auth|activation|license|secret_key|api_key|access_key|client_secret|encryption_key)"

is_password_name(name) {
    regex.match(password_pattern, name)
}

check_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    variable := glitch_lib.all_variables(unit_block)[_]
    is_password_name(variable.name)
    check_empty_value(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": unit_block.path,
        "description": "Empty password in configuration file - CWE-258"
    }
}

Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    attribute := glitch_lib.all_attributes(unit_block)[_]
    is_password_name(attribute.name)
    check_empty_value(attribute.value)
    result := {
        "type": "sec_empty_pass",
        "element": attribute,
        "path": unit_block.path,
        "description": "Empty password in configuration file - CWE-258"
    }
}

Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    variable := glitch_lib.all_variables(unit_block)[_]
    variable.value.ir_type == "Hash"
    walk(variable.value, [path, node])
    node.ir_type == "Hash"
    hash_dict := node.value
    key_expr := _
    value_expr := hash_dict[key_expr]
    key_expr.ir_type == "String"
    is_password_name(key_expr.value)
    check_empty_value(value_expr)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": unit_block.path,
        "description": "Empty password in configuration file - CWE-258"
    }
}

Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    attribute := glitch_lib.all_attributes(unit_block)[_]
    attribute.value.ir_type == "Hash"
    walk(attribute.value, [path, node])
    node.ir_type == "Hash"
    hash_dict := node.value
    key_expr := _
    value_expr := hash_dict[key_expr]
    key_expr.ir_type == "String"
    is_password_name(key_expr.value)
    check_empty_value(value_expr)
    result := {
        "type": "sec_empty_pass",
        "element": attribute,
        "path": unit_block.path,
        "description": "Empty password in configuration file - CWE-258"
    }
}