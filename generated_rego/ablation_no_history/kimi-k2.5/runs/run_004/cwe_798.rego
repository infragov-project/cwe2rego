package glitch

import data.glitch_lib

suspicious_keywords := {"password", "passwd", "pwd", "secret", "secrets", "api_secret", "secret_key", "api_key", "private_key", "token", "access_token", "auth_token", "bearer_token", "credential", "credentials", "admin_pass", "root_password", "master_password"}

contains_credential_keyword(key) {
    kw := suspicious_keywords[_]
    contains(lower(key), kw)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not contains(value.value, "{{")
    not contains(value.value, "${")
    not contains(value.value, "vault(")
    not contains(value.value, "lookup(")
}

is_literal_credential_value(value) {
    is_hardcoded_string(value)
}

check_hash_entry(key, value) {
    key.ir_type == "String"
    contains_credential_keyword(key.value)
    is_literal_credential_value(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    check_hash_entry(entry.key, entry.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hardcoded in configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    
    contains_credential_keyword(node.name)
    is_literal_credential_value(node.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hardcoded in configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    contains_credential_keyword(var.name)
    is_literal_credential_value(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hardcoded in configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    contains_credential_keyword(attr.name)
    is_literal_credential_value(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hardcoded in configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    walk(au, [_, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    check_hash_entry(entry.key, entry.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hardcoded in configuration. (CWE-798)"
    }
}