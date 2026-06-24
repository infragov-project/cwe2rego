package glitch

import data.glitch_lib

password_pattern = `(?i)\b(password|passwd|pwd|secret|key|token|api_key|auth_token|credential|access_key|secret_key|private_key)\b`

is_password_field(name) {
    regex.match(password_pattern, name)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_chef_namespace(name) {
    regex.match(`^[a-zA-Z_]+\[`, name)
}

all_vars_in_parent(parent) = vars {
    parent.type == "vars"
    vars = set()
} else = vars {
    not (parent.type == "vars")
    all := glitch_lib.all_variables(parent)
    vars = {v | v := all[_]; not is_chef_namespace(v.name)}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    node := attrs[_]
    is_password_field(node.name)
    is_empty_value(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty. (CWE-258)",
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node := all_vars_in_parent(parent)[_]
    is_password_field(node.name)
    is_empty_value(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty. (CWE-258)",
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    node := attrs[_]
    node.value.ir_type == "FunctionCall"
    is_password_field(node.name)
    arg := node.value.args[_]
    is_empty_value(arg)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty. (CWE-258)",
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    node := attrs[_]
    node.value.ir_type == "FunctionCall"
    is_password_field(node.name)
    arg := node.value.args[_]
    arg.ir_type == "VariableReference"
    is_password_field(arg.value)
    referenced_var_has_empty_default(arg.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication credentials should not be empty. (CWE-258)",
    }
}

referenced_var_has_empty_default(varname) {
    vars := all_vars_in_parent(input)
    v := vars[_]
    v.name == varname
    is_empty_value(v.value)
}

referenced_var_has_empty_default(varname) {
    block := all_blocks[_]
    code_has_empty_var(block.code, varname)
}

all_blocks[block] {
    walk(input, [_, block])
    block.ir_type == "UnitBlock"
}

code_has_empty_var(code, varname) {
    regex.match(sprintf(`(?i)[$]\s*%s\s*=\s*['"]\s*['"]`, [varname]), code)
} else {
    regex.match(sprintf(`(?i)\b%s\s*=\s*['"]\s*['"]`, [varname]), code)
} else {
    regex.match(sprintf(`(?i)[$]\s*%s\s*=\s*nil\b`, [varname]), code)
} else {
    regex.match(sprintf(`(?i)\b%s\s*[:=]\s*nil\b`, [varname]), code)
} else {
    regex.match(sprintf(`(?i)[$]\s*%s\s*=\s*null\b`, [varname]), code)
} else {
    regex.match(sprintf(`(?i)\b%s\s*[:=]\s*null\b`, [varname]), code)
}