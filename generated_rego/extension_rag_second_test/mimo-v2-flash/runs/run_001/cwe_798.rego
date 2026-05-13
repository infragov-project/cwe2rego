package glitch

import data.glitch_lib

secret_keywords := {"password", "secret", "apikey", "token", "credential", "private_key", "secret_key", "auth_string", "connection_string", "username", "default_password", "initial_token", "builtin_credential", "encryption_key", "signing_key", "certificate_body", "endpoint_url", "database_url", "user"}

is_secret_key(key) {
    pattern := secret_keywords[_]
    regex.match(sprintf("(?i)\\b%s\\b", [pattern]), key)
}

is_hardcoded_primitive(value) {
    value.ir_type == "String"
} else {
    value.ir_type == "Integer"
} else {
    value.ir_type == "Float"
} else {
    value.ir_type == "Boolean"
} else {
    value.ir_type == "Null"
}

check_hardcoded_secret(node, path) {
    walk(node, [p, n])
    is_hardcoded_primitive(n)
    count(p) > 0
    key := p[count(p) - 1]
    is_secret_key(key)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    is_hardcoded_primitive(var.value)
    is_secret_key(var.name)
    not var.value.ir_type == "VariableReference"
    not var.value.ir_type == "FunctionCall"
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential in variable - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    is_hardcoded_primitive(attr.value)
    is_secret_key(attr.name)
    not attr.value.ir_type == "VariableReference"
    not attr.value.ir_type == "FunctionCall"
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in attribute - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    check_hardcoded_secret(var.value, [])
    not var.value.ir_type == "VariableReference"
    not var.value.ir_type == "FunctionCall"
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential in variable (nested) - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    check_hardcoded_secret(attr.value, [])
    not attr.value.ir_type == "VariableReference"
    not attr.value.ir_type == "FunctionCall"
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in attribute (nested) - Avoid using hard-coded credentials. (CWE-798)"
    }
}