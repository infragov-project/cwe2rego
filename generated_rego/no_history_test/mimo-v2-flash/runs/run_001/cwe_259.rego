package glitch

import data.glitch_lib

secret_keywords := {"password", "pass", "secret", "token", "key", "credential", "auth", "admin_password", "db_password", "sha512_password"}
weak_defaults := {"admin", "password", "123456", "changeme", "12345", "letmein", "welcome", "qwerty", "telarista"}

matches_secret_keyword(name) {
    contains(name, secret_keywords[_])
}

is_hardcoded_secret(value_expr) {
    value_expr.ir_type == "String"
    value_expr.value != ""
    not glitch_lib.traverse_var(value_expr)
}

is_weak_default(value_expr) {
    value_expr.ir_type == "String"
    weak_defaults[_] == value_expr.value
    not glitch_lib.traverse_var(value_expr)
}

# Rule for hash key-value pairs at any depth
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    key_expr := kv.key
    value_expr := kv.value
    key_expr.ir_type == "String"
    matches_secret_keyword(key_expr.value)
    (is_hardcoded_secret(value_expr) or is_weak_default(value_expr))
    result := {
        "type": "sec_hard_pass",
        "element": key_expr,
        "path": parent.path,
        "description": "Hard-coded or weak default password in configuration (CWE-259)"
    }
}

# Rule for variables with string values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    matches_secret_keyword(var.name)
    var.value.ir_type == "String"
    (is_hardcoded_secret(var.value) or is_weak_default(var.value))
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded password in variable (CWE-259)"
    }
}

# Rule for attributes in atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    matches_secret_keyword(attr.name)
    (is_hardcoded_secret(attr.value) or is_weak_default(attr.value))
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in resource configuration (CWE-259)"
    }
}