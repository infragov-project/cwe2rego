package glitch

import data.glitch_lib

password_keywords := {"password", "secret", "passphrase", "token", "credential", "auth", "key", "pwd", "activationkey", "ssh_password", "api_token", "proxy_password"}

connection_string_attrs := {"connection_string", "jdbc_url", "dsn"}

is_password_like(name) {
    some keyword
    password_keywords[keyword]
    contains(lower(name), keyword)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} {
    value.ir_type == "Null"
} {
    value.ir_type == "Undef"
}

is_empty_connection_string(value) {
    value.ir_type == "String"
    regex.match("(?i)pwd=([;'\"]|$)", value.value)
} {
    value.ir_type == "String"
    regex.match("(?i)password=([;'\"]|$)", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    is_password_like(node.name)
    is_empty_value(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - The password field is set to an empty value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    is_password_like(node.name)
    is_empty_value(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - The password field is set to an empty value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    lower_name := lower(node.name)
    connection_string_attrs[_] == lower_name
    is_empty_connection_string(node.value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in connection string - The connection string contains an empty password parameter. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some kv in node.value
    is_password_like(kv.key.value)
    is_empty_value(kv.value)
    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty password in configuration file - The password field is set to an empty value. (CWE-258)"
    }
}