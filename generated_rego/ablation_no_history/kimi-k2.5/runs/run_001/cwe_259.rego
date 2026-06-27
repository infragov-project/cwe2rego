package glitch

import data.glitch_lib

password_field_patterns := ["password", "passwd", "pwd", "secret", "credentials", "auth", "authentication", "login_pass", "admin_password", "root_password", "master_password", "user_password", "db_password", "database_password", "service_password", "api_password", "token", "api_key", "access_key", "secret_key", "private_key", "passphrase", "sha512_password", "pre_shared_key", "preshared_key", "shared_secret", "tunnel_password", "key"]

default_passwords := ["admin", "password", "123456", "default", "qwerty", "letmein", "passw0rd", "telarista", "some_password", "pass"]

is_password_field(name) {
    lower_field := lower(name)
    pattern := password_field_patterns[_]
    contains(lower_field, pattern)
}

is_false_positive_field(name) {
    lower_name := lower(name)
    contains(lower_name, "authenticator")
} else {
    lower_name := lower(name)
    contains(lower_name, "authorizer")
} else {
    lower_name := lower(name)
    endswith(lower_name, "_keystore")
} else {
    lower_name := lower(name)
    contains(lower_name, "enable")
    not contains(lower_name, "secret")
} else {
    lower_name := lower(name)
    startswith(lower_name, "no_")
    contains(lower_name, "password")
}

looks_like_credential(str) {
    count(str) >= 4
    not str == ""
    not regex.match("^[a-zA-Z][a-zA-Z0-9_-]{0,30}$", str)
} else {
    default_pw := default_passwords[_]
    lower_str := lower(str)
    lower_str == default_pw
} else {
    regex.match("^[A-Za-z0-9+/]+={0,2}$", str)
    count(str) >= 8
} else {
    regex.match("^\\$[0-9a-zA-Z]+\\$", str)
}

is_secure_reference(node) {
    node.ir_type == "VariableReference"
} else {
    node.ir_type == "FunctionCall"
} else {
    node.ir_type == "MethodCall"
}

check_password_value(node, key_name) {
    node.ir_type == "String"
    not is_secure_reference(node)
    looks_like_credential(node.value)
    is_password_field(key_name)
    not is_false_positive_field(key_name)
}

collect_all_keyvalues(node) = keyvalues {
    keyvalues = {kv |
        walk(node, [path, n])
        n.ir_type == "KeyValue"
        kv := n
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_kvs := collect_all_keyvalues(parent)
    kv := all_kvs[_]
    
    check_password_value(kv.value, kv.name)
    
    result := {
        "type": "sec_hard_pass",
        "element": kv,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded and should be retrieved from secure secret management systems. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, hash])
    hash.ir_type == "Hash"
    
    some k, v
    hash.value[k] = v
    
    k.ir_type == "String"
    check_password_value(v, k.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": {"key": k, "value": v},
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded and should be retrieved from secure secret management systems. (CWE-259)"
    }
}