package glitch

import data.glitch_lib
import future.keywords.in

credential_keywords := {"password", "secret", "key", "token", "auth", "credential", "passwd", "pwd", "apikey", "accesskey", "secretkey", "username", "truststore", "user"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    
    key.ir_type == "String"
    some keyword in credential_keywords
    glitch_lib.contains(key.value, keyword)
    
    value.ir_type == "String"
    not is_false_positive_key(key.value, value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": key,
        "path": parent.path,
        "description": "Use of hard-coded credentials in attribute - Avoid embedding sensitive data like passwords, keys, or tokens in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    some keyword in credential_keywords
    glitch_lib.contains(var.name, keyword)
    var.value.ir_type == "String"
    not is_false_positive_variable(var.name, var.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials in variable - Avoid embedding sensitive data like passwords, keys, or tokens in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    
    some keyword in credential_keywords
    glitch_lib.contains(attr.name, keyword)
    attr.value.ir_type == "String"
    not is_false_positive_key(attr.name, attr.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in attribute - Avoid embedding sensitive data like passwords, keys, or tokens in code. (CWE-798)"
    }
}

is_false_positive_key(key_name, value) {
    regex.match(".*_attribute$", key_name)
}

is_false_positive_key(key_name, value) {
    regex.match(".*_dn$", key_name)
}

is_false_positive_key(key_name, value) {
    regex.match("^https?://", value)
}

is_false_positive_key(key_name, value) {
    regex.match("^org\\.", value)
}

is_false_positive_key(key_name, value) {
    value in {"person", "Default", "uid", "cn", "dc", "mail", "groupOfNames", "nsAccountLock"}
}

is_false_positive_key(key_name, value) {
    regex.match("^/", value)
}

is_false_positive_key(key_name, value) {
    regex.match("^[a-zA-Z]:\\\\", value)
}

is_false_positive_key(key_name, value) {
    key_name == "auth_type"
    value == "password"
}

is_false_positive_key(key_name, value) {
    regex.match("^[^=]+=.*,[^=]+=.*,[^=]+=", value)
}

is_false_positive_variable(var_name, value) {
    regex.match(".*admin_user$", var_name)
}

is_false_positive_variable(var_name, value) {
    regex.match("^https?://", value)
}

is_false_positive_variable(var_name, value) {
    regex.match("^org\\.", value)
}

is_false_positive_variable(var_name, value) {
    value in {"person", "Default", "uid", "cn", "dc", "mail", "groupOfNames", "nsAccountLock"}
}

is_false_positive_variable(var_name, value) {
    regex.match("^/", value)
}

is_false_positive_variable(var_name, value) {
    regex.match("^[a-zA-Z]:\\\\", value)
}