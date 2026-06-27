package glitch

import data.glitch_lib

password_patterns_1 := {"password", "passwd", "pwd", "pass"}
key_patterns := {"key", "token", "secret"}
auth_patterns := {"credential", "auth"}

check_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
}

check_empty_password(value) {
    value.ir_type == "Null"
}

check_empty_password(value) {
    value.ir_type == "Undef"
}

is_password_attribute(name) {
    lower_name := lower(name)
    contains(lower_name, password_patterns_1[_])
    not exclude_password_pattern(lower_name)
}

is_password_attribute(name) {
    lower_name := lower(name)
    contains(lower_name, key_patterns[_])
    not exclude_key_pattern(lower_name)
}

is_password_attribute(name) {
    lower_name := lower(name)
    contains(lower_name, auth_patterns[_])
    not exclude_auth_pattern(lower_name)
}

exclude_password_pattern(name) {
    contains(name, "proxy_password")
}

exclude_key_pattern(name) {
    contains(name, "api_token")
}

exclude_key_pattern(name) {
    contains(name, "cache")
}

exclude_key_pattern(name) {
    contains(name, "keyring")
}

exclude_key_pattern(name) {
    contains(name, "sslclientkey")
}

exclude_key_pattern(name) {
    contains(name, "sslclientcert")
}

exclude_auth_pattern(name) {
    false
}

all_keyvalues(node) = keyvals {
    keyvals = {kv |
        walk(node, [path, kv])
        kv.ir_type == "Variable"
    } | {kv |
        walk(node, [path, kv])
        kv.ir_type == "Attribute"
    }
}

find_empty_in(node) {
    walk(node, [_, n])
    check_empty_password(n)
}

find_var_ref_in(node) = var_refs {
    var_refs = {ref |
        walk(node, [_, n])
        n.ir_type == "VariableReference"
        ref := n.value
    }
}

get_all_params_from_blocks(node) = params {
    params = {p |
        walk(node, [path, ub])
        ub.ir_type == "UnitBlock"
        walk(ub, [path2, attr])
        attr.ir_type == "Attribute"
        p := {"name": attr.name, "value": attr.value}
    } | {p |
        walk(node, [path, ub])
        ub.ir_type == "UnitBlock"
        walk(ub, [path2, var])
        var.ir_type == "Variable"
        p := {"name": var.name, "value": var.value}
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    all_kvs := all_keyvalues(parent)
    kv := all_kvs[_]
    
    is_password_attribute(kv.name)
    check_empty_password(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Using an empty string as a password is insecure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    all_kvs := all_keyvalues(parent)
    kv := all_kvs[_]
    
    is_password_attribute(kv.name)
    not check_empty_password(kv.value)
    find_empty_in(kv.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Using an empty string as a password is insecure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    all_kvs := all_keyvalues(parent)
    kv := all_kvs[_]
    
    is_password_attribute(kv.name)
    
    var_refs := find_var_ref_in(kv.value)
    ref_name := var_refs[_]
    
    all_params := get_all_params_from_blocks(parent)
    param := all_params[_]
    param.name == ref_name
    check_empty_password(param.value)

    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Using an empty string as a password is insecure. (CWE-258)"
    }
}