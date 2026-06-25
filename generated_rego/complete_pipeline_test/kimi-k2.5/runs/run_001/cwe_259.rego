package glitch

import data.glitch_lib

password_indicators := ["password", "passwd", "pwd", "secret", "credentials", "auth_token", "api_key", "access_key", "private_key", "_password", "_secret", "_key", "pass"]

is_password_related_name(name) {
    lower_name := lower(name)
    indicator := password_indicators[_]
    contains(lower_name, indicator)
}

is_password_related_name(name) {
    lower_name := lower(name)
    lower_name == "key"
}

is_hardcoded_string_value(val) {
    val.ir_type == "String"
    not looks_like_variable_ref(val.value)
    not looks_like_secret_ref(val.value)
    val.value != ""
    not is_placeholder_value(val.value)
}

looks_like_variable_ref(str) {
    regex.match("^\\$\\{.*\\}$", str)
}

looks_like_variable_ref(str) {
    regex.match("^(var|data|module|local|each|count)\\.", str)
}

looks_like_variable_ref(str) {
    regex.match("^\\{", str)
}

looks_like_secret_ref(str) {
    regex.match("(?i)vault|secret|parameter|keyvault|secretsmanager|kms|hashicorp|getenv|get_secret|read_secret|data_source|lookup", str)
}

is_placeholder_value(str) {
    lower_str := lower(str)
    lower_str == "null"
}

is_placeholder_value(str) {
    lower_str := lower(str)
    lower_str == "none"
}

is_placeholder_value(str) {
    lower_str := lower(str)
    lower_str == "true"
}

is_placeholder_value(str) {
    lower_str := lower(str)
    lower_str == "false"
}

is_placeholder_value(str) {
    regex.match("^[${]+[}$]+$", str)
}

contains_password_in_env_string(str) {
    regex.match("(?i)(password|passwd|pwd|secret|credentials|auth_token|api_key|access_key|private_key|_password|_secret|_key|pass|passwd)=", str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_password_related_name(var.name)
    is_hardcoded_string_value(var.value)

    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Sensitive credentials should not be hardcoded; use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomics := glitch_lib.all_atomic_units(parent)
    atomic := atomics[_]
    
    attrs := glitch_lib.all_attributes(atomic)
    attr := attrs[_]
    
    is_password_related_name(attr.name)
    is_hardcoded_string_value(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Sensitive credentials should not be hardcoded; use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, node])
    
    node.ir_type == "Hash"
    entry := node.value[_]
    
    entry.key.ir_type == "String"
    is_password_related_name(entry.key.value)
    entry.value.ir_type == "String"
    is_hardcoded_string_value(entry.value)

    result := {
        "type": "sec_hard_pass",
        "element": entry,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Sensitive credentials should not be hardcoded; use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, node])
    
    node.ir_type == "Array"
    elem := node.value[_]
    
    elem.ir_type == "String"
    contains_password_in_env_string(elem.value)
    not looks_like_variable_ref(elem.value)
    not looks_like_secret_ref(elem.value)
    elem.value != ""

    result := {
        "type": "sec_hard_pass",
        "element": elem,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Sensitive credentials should not be hardcoded; use secret management systems instead. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, node])
    
    node.ir_type == "Sum"
    node.left.ir_type == "String"
    contains_password_in_env_string(node.left.value)
    is_hardcoded_string_value(node.left)

    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Sensitive credentials should not be hardcoded; use secret management systems instead. (CWE-259)"
    }
}