package glitch

import data.glitch_lib

sensitive_keywords := {"password", "secret", "token", "api_key", "key", "credential", "auth", "passphrase", "private_key", "ssh_key", "bearer_token", "admin_password", "admin", "root", "guest", "ubnt", "changeme"}

hardcoded_patterns := {"password123", "admin", "letmein", "changeme", "AKIAIOSFODNN7EXAMPLE", "cGFzc3dvcmQxMjM=", "RedHat1!", "password", "telarista"}

default_credentials := {"admin", "root", "password"}

check_hardcoded_string(value) {
    value.ir_type == "String"
    some pattern
    hardcoded_patterns[pattern]
    value.value == pattern
} else {
    value.ir_type == "String"
    lower_str := lower(value.value)
    some keyword
    sensitive_keywords[keyword]
    contains(lower_str, keyword)
}

check_hardcoded_complex(complex) {
    complex.ir_type == "Hash"
    some key_expr, value_expr
    complex.value[key_expr]
    check_hardcoded_string(key_expr)
} else {
    complex.ir_type == "Hash"
    some key_expr, value_expr
    complex.value[key_expr]
    check_hardcoded_string(value_expr)
} else {
    complex.ir_type == "Array"
    some expr
    complex.value[expr]
    check_hardcoded_string(expr)
}

check_hardcoded_credential(node) {
    check_hardcoded_string(node.value)
} else {
    check_hardcoded_complex(node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    some keyword
    sensitive_keywords[keyword]
    contains(lower(var.name), keyword)
    
    check_hardcoded_credential(var)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    some keyword
    sensitive_keywords[keyword]
    contains(lower(attr.name), keyword)
    
    check_hardcoded_credential(attr)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    lower_name := lower(var.name)
    some cred
    default_credentials[cred]
    contains(lower_name, cred)
    
    check_hardcoded_credential(var)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded default credentials - Avoid default credentials in IaC scripts. (CWE-798)"
    }
}