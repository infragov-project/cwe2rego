package glitch

import data.glitch_lib

sensitive_keywords := {"password", "secret", "key", "token", "credential", "auth_string", "api_key", "private_key", "ssh_key", "certificate", "passphrase", "admin_password", "default_password", "root_password", "db_admin", "service_account_key", "access_key", "secret_key", "client_secret", "jwt_secret", "encryption_key", "connection_string", "dsn", "jdbc_url", "endpoint"}

contains_sensitive_keyword(s) = true {
    some keyword
    keyword = sensitive_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), s)
}

check_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
}

check_hardcoded_number(value) {
    value.ir_type == "Integer"
}

check_hardcoded_boolean(value) {
    value.ir_type == "Boolean"
}

check_hardcoded_value(value) {
    check_hardcoded_string(value)
} else {
    check_hardcoded_number(value)
} else {
    check_hardcoded_boolean(value)
}

check_hash_for_hardcoded_credentials(value) {
    value.ir_type == "Hash"
    walk(value, [path, node])
    node.ir_type == "String"
    node.value != ""
    key := path[count(path) - 2]
    contains_sensitive_keyword(key)
}

check_array_for_hardcoded_credentials(value) {
    value.ir_type == "Array"
    walk(value, [path, node])
    node.ir_type == "String"
    node.value != ""
    parent_key := path[count(path) - 2]
    contains_sensitive_keyword(parent_key)
}

Glitch_Analysis[result] {
    [path, node] := walk(input)
    node.ir_type == "Variable"
    contains_sensitive_keyword(node.name)
    check_hardcoded_value(node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [_, n])
    n == node
    parent.path != ""
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    [path, node] := walk(input)
    node.ir_type == "Variable"
    contains_sensitive_keyword(node.name)
    check_hash_for_hardcoded_credentials(node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [_, n])
    n == node
    parent.path != ""
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    [path, node] := walk(input)
    node.ir_type == "Variable"
    contains_sensitive_keyword(node.name)
    check_array_for_hardcoded_credentials(node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [_, n])
    n == node
    parent.path != ""
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    [path, node] := walk(input)
    node.ir_type == "Attribute"
    contains_sensitive_keyword(node.name)
    check_hardcoded_value(node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [_, n])
    n == node
    parent.path != ""
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    [path, node] := walk(input)
    node.ir_type == "Attribute"
    contains_sensitive_keyword(node.name)
    check_hash_for_hardcoded_credentials(node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [_, n])
    n == node
    parent.path != ""
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    [path, node] := walk(input)
    node.ir_type == "Attribute"
    contains_sensitive_keyword(node.name)
    check_array_for_hardcoded_credentials(node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [_, n])
    n == node
    parent.path != ""
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential - Avoid using hard-coded credentials. (CWE-798)"
    }
}