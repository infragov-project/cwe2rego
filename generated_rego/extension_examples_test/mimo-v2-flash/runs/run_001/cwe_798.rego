package glitch

import data.glitch_lib

sensitive_keywords := {"password", "secret", "key", "token", "credential", "passphrase", "auth", "user", "sha512_password", "private_key", "api_key", "db_secret", "access_token", "admin_password"}

contains_sensitive_keyword(name) {
    lower_name := lower(name)
    some kw in sensitive_keywords
    contains(lower_name, kw)
}

is_static_value(expr) {
    expr.ir_type in {"String", "Integer", "Float", "Boolean", "Null", "Complex", "Undef"}
}

is_variable_reference(expr) {
    expr.ir_type == "VariableReference"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Variable"
    contains_sensitive_keyword(n.name)
    not is_variable_reference(n.value)
    is_static_value(n.value)
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": "Use of hard-coded credentials - The code contains a hard-coded credential which could expose sensitive information. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Attribute"
    contains_sensitive_keyword(n.name)
    not is_variable_reference(n.value)
    is_static_value(n.value)
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": "Use of hard-coded credentials - The code contains a hard-coded credential which could expose sensitive information. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Hash"
    some kv in n.value
    kv.key.ir_type == "String"
    contains_sensitive_keyword(kv.key.value)
    not is_variable_reference(kv.value)
    is_static_value(kv.value)
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": "Use of hard-coded credentials - The code contains a hard-coded credential which could expose sensitive information. (CWE-798)"
    }
}