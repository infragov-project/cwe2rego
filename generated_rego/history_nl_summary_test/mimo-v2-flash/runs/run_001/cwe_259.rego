package glitch

import data.glitch_lib

password_keywords := {"password", "secret", "token", "credential", "passphrase", "admin_password", "master_key", "db_password", "private_key", "api_key", "access_token", "service_key", "keystore_password", "truststore_password", "key", "auth"}

weak_patterns := {"admin", "password", "123456", "changeme", "test", "example", "default", "telarista"}

contains_password_keyword(str) {
    keyword := password_keywords[_]
    regex.match(sprintf("(?i)%s", [keyword]), str)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    not contains(value.value, "{{")
    not contains(value.value, "{%")
    not contains(value.value, "$(")
    not contains(value.value, "`")
}

is_dynamic_value(value) {
    value.ir_type == "VariableReference"
} else {
    value.ir_type == "FunctionCall"
} else {
    value.ir_type == "MethodCall"
}

is_weak_password(value) {
    value.ir_type == "String"
    pattern := weak_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    contains_password_keyword(attr.name)
    
    not is_dynamic_value(attr.value)
    attr.value.ir_type == "String"
    is_hardcoded_string(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Hard-coded credentials in IaC scripts can lead to unauthorized access. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    
    contains_password_keyword(variable.name)
    
    not is_dynamic_value(variable.value)
    variable.value.ir_type == "String"
    is_hardcoded_string(variable.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded password - Hard-coded credentials in IaC scripts can lead to unauthorized access. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "String"
    is_hardcoded_string(node)
    contains_password_keyword(node.value)
    
    count(path) >= 2
    parent_key := path[count(path) - 2]
    parent_key.ir_type == "String"
    not contains_password_keyword(parent_key.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Hard-coded credentials in IaC scripts can lead to unauthorized access. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    attr.value.ir_type == "String"
    is_hardcoded_string(attr.value)
    is_weak_password(attr.value)
    
    contains_password_keyword(attr.name)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Hard-coded credentials in IaC scripts can lead to unauthorized access. (CWE-259)"
    }
}