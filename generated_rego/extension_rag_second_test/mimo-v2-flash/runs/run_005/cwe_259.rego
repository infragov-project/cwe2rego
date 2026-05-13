package glitch

import data.glitch_lib

password_keywords := {"password", "admin_password", "secret_key", "api_key", "token", "credential", "auth_string", "pwd", "key", "secret"}

is_file_path(value) {
    regex.match(`^(?:\.\.?/|/|[A-Za-z]:\\)`, value)
} else {
    regex.match(`\.(keystore|truststore|jks|p12|pem|crt|key|json|yaml|yml|txt|conf|ini)$`, value)
} else {
    regex.match(`[\\/].*[\\/]`, value)
}

is_hardcoded_password(str) {
    lower_str := lower(str)
    some keyword
    password_keywords[keyword]
    contains(lower_str, keyword)
    not is_file_path(str)
}

find_password_entries(hash_node) = passwords {
    passwords := {entry |
        walk(hash_node, [path, node])
        node.ir_type == "Hash"
        entry := node.value[_]
        entry.key.ir_type == "String"
        key_lower := lower(entry.key.value)
        some keyword
        password_keywords[keyword]
        contains(key_lower, keyword)
        entry.value.ir_type == "String"
        not is_file_path(entry.value.value)
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    is_hardcoded_password(var.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    passwords := find_password_entries(var.value)
    count(passwords) > 0
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    is_hardcoded_password(attr.value.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    passwords := find_password_entries(attr.value)
    count(passwords) > 0
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}