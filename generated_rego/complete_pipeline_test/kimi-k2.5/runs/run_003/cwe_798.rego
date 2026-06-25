package glitch

import data.glitch_lib
import future.keywords.in

cred_keywords := {"password", "passwd", "pwd", "secret", "token", "key", "api_key", "apikey", "access_key", "secret_key", "private_key", "credential", "auth_token", "sha512_password", "sha256_password", "md5_password", "bcrypt_password"}

weak_passwords := {"admin", "password", "123456", "default", "changeme", "guest", "user", "login", "qwerty", "letmein", "welcome", "telarista", "password123", "12345678", "abc123", "monkey", "dragon"}

skip_attributes := {"name", "description", "enabled", "type", "id", "version", "tags", "metadata", "labels", "annotations", "comment", "comments", "note", "notes", "display_name", "title", "summary"}

contains_cred_keyword(s) {
    lower_s := lower(s)
    cred_keywords[kw]
    endswith(lower_s, kw)
}

contains_cred_keyword(s) {
    lower_s := lower(s)
    cred_keywords[kw]
    startswith(lower_s, kw)
}

contains_cred_keyword(s) {
    lower_s := lower(s)
    cred_keywords[kw]
    contains(lower_s, sprintf("_%s_", [kw]))
}

is_hardcoded_secret(val) {
    val.ir_type == "String"
    count(val.value) > 0
    not looks_like_reference(val.value)
}

is_weak_password(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    weak_passwords[weak_pw]
    lower_val == weak_pw
}

looks_like_reference(s) {
    regex.match("^\\$\\{.*\\}$", s)
}

looks_like_reference(s) {
    regex.match("^vault::", s)
}

looks_like_reference(s) {
    regex.match("^\\${?\\w+", s)
}

looks_like_reference(s) {
    regex.match("^!\\w+", s)
}

looks_like_reference(s) {
    regex.match("^\\{\\{.*\\}\\}$", s)
}

looks_like_reference(s) {
    regex.match("^lookup\\s*\\(", s)
}

looks_like_reference(s) {
    regex.match("^data\\.", s)
}

looks_like_reference(s) {
    regex.match("^module\\.", s)
}

looks_like_reference(s) {
    regex.match("^var\\.", s)
}

looks_like_reference(s) {
    regex.match("^local\\.", s)
}

is_cred_key(key_name) {
    cred_keywords[kw]
    endswith(key_name, kw)
}

is_cred_key(key_name) {
    cred_keywords[kw]
    startswith(key_name, kw)
}

is_cred_key(key_name) {
    cred_keywords[kw]
    contains(key_name, sprintf("_%s_", [kw]))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_cred_keyword(var.name)
    var.value.ir_type == "String"
    is_hardcoded_secret(var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Variable '%s' contains hardcoded credential. Use secret management systems instead. (CWE-798)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    walk(var.value, [path, n])
    n.ir_type == "String"
    count(n.value) > 0
    not looks_like_reference(n.value)
    path[_].ir_type == "Hash"
    path[_].key.ir_type == "String"
    key_name := lower(path[_].key.value)
    is_cred_key(key_name)
    not skip_attributes[key_name]
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Hardcoded value found for credential key '%s' in variable '%s'. Use secret management systems instead. (CWE-798)", [key_name, var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Array"
    some i
    i == numbers.range(0, count(var.value.value) - 1)[_]
    arr_val_var := var.value.value[i]
    arr_val_var.ir_type == "Hash"
    walk(arr_val_var, [path, n])
    n.ir_type == "String"
    count(n.value) > 0
    not looks_like_reference(n.value)
    path[_].ir_type == "Hash"
    path[_].key.ir_type == "String"
    key_name := lower(path[_].key.value)
    is_cred_key(key_name)
    not skip_attributes[key_name]
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Hardcoded value found for credential key '%s' in array variable '%s' at index %d. Use secret management systems instead. (CWE-798)", [key_name, var.name, i])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    lower_name := lower(attr.name)
    not skip_attributes[lower_name]
    contains_cred_keyword(attr.name)
    attr.value.ir_type == "String"
    is_hardcoded_secret(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Attribute '%s' in '%s' contains hardcoded credential. Use secret management systems instead. (CWE-798)", [attr.name, au.type])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    walk(attr.value, [path, n])
    n.ir_type == "String"
    count(n.value) > 0
    not looks_like_reference(n.value)
    path[_].ir_type == "Hash"
    path[_].key.ir_type == "String"
    key_name := lower(path[_].key.value)
    is_cred_key(key_name)
    not skip_attributes[key_name]
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Hardcoded value found for credential key '%s' in attribute '%s' of '%s'. Use secret management systems instead. (CWE-798)", [key_name, attr.name, au.type])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    some i
    i == numbers.range(0, count(attr.value.value) - 1)[_]
    arr_val_attr := attr.value.value[i]
    arr_val_attr.ir_type == "Hash"
    walk(arr_val_attr, [path, n])
    n.ir_type == "String"
    count(n.value) > 0
    not looks_like_reference(n.value)
    path[_].ir_type == "Hash"
    path[_].key.ir_type == "String"
    key_name := lower(path[_].key.value)
    is_cred_key(key_name)
    not skip_attributes[key_name]
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Hardcoded value found for credential key '%s' in attribute '%s' of '%s' at index %d. Use secret management systems instead. (CWE-798)", [key_name, attr.name, au.type, i])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_cred_keyword(var.name)
    var.value.ir_type == "String"
    is_weak_password(var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Weak/default password detected in '%s'. Use strong, non-default credentials managed by a secret management system. (CWE-798)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    contains_cred_keyword(attr.name)
    attr.value.ir_type == "String"
    is_weak_password(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Credentials - Weak/default password detected in attribute '%s' of '%s'. Use strong, non-default credentials managed by a secret management system. (CWE-798)", [attr.name, au.type])
    }
}