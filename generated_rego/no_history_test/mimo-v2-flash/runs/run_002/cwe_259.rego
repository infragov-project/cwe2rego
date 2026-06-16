package glitch

import data.glitch_lib

sensitive_keywords = {"password", "secret", "api_key", "access_key", "secret_key", "token", "credential", "auth", "key", "pass", "passwd", "connection_string", "admin_password", "root_password", "master_password", "initial_password", "sha512_password", "keystore_password", "truststore_password"}

common_passwords = {"admin", "password", "123456", "changeme", "tiger", "scott", "default", "root", "12345678", "qwerty", "cassandra", "some_password"}

connection_string_pattern = `(?i)(user|username|uid|password|pwd|pass)=[^;@]+[@;]`
password_assignment_pattern = `(?i)(password|passwd|pwd)=.+`

is_sensitive_name(name) {
    regex.match(sprintf("(?i).*\\b(%s)\\b", [concat("|", sensitive_keywords)]), name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    not glitch_lib.has_variable_reference(value)
}

is_hardcoded_password_string(value) {
    is_hardcoded_string(value)
    value.value != ""
    regex.match(connection_string_pattern, value.value)
}

is_hardcoded_password_string(value) {
    is_hardcoded_string(value)
    value.value != ""
    regex.match(password_assignment_pattern, value.value)
}

is_hardcoded_password_string(value) {
    is_hardcoded_string(value)
    value.value != ""
    common_passwords[lower(value.value)]
}

check_sensitive_value(value) {
    is_hardcoded_string(value)
    value.value != ""
}

check_sensitive_value(value) {
    value.ir_type == "Array"
    item := value.value[_]
    is_hardcoded_password_string(item)
}

check_sensitive_value(value) {
    value.ir_type == "Hash"
    pair := value.value[_]
    is_hardcoded_password_string(pair.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_sensitive_name(attr.name)
    check_sensitive_value(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password in resource definition (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    is_sensitive_name(var.name)
    check_sensitive_value(var.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded password in variable definition (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Hash"
    pair := n.value[_]
    key_string := pair.key.value
    value_expr := pair.value
    is_sensitive_name(key_string)
    check_sensitive_value(value_expr)
    
    result := {
        "type": "sec_hard_pass",
        "element": pair.key,
        "path": parent.path,
        "description": "Hard-coded password in nested structure (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Array"
    item := n.value[_]
    item.ir_type == "String"
    is_hardcoded_password_string(item)
    
    result := {
        "type": "sec_hard_pass",
        "element": item,
        "path": parent.path,
        "description": "Hard-coded password in array (CWE-259)"
    }
}