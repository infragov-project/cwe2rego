package glitch

import data.glitch_lib

high_conf_credential_names := {
    "password", "passwd", "pass", "pwd", "secret",
    "token", "credential", "apikey", "api_key", "htpasswd",
    "keystore", "truststore", "key", "access_key", "private_key",
    "encryption_key", "signing_key", "client_secret",
    "secret_key", "auth_token", "authkey"
}

connection_names := {
    "connection_string", "jdbc_url", "conn_str", "connection_url",
    "uri", "endpoint", "url"
}

default_weak := {
    "admin", "password", "guest", "changeme", "default",
    "root", "toor", "master", "123456", "12345678",
    "qwerty", "abc123", "letmein", "monkey", "dragon",
    "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "princess", "football", "shadow", "michael", "hello", "charlie"
}

well_known_usernames := {
    "root", "administrator", "admin", "guest", "default",
    "postgres", "mysql", "nobody", "www-data", "ubuntu",
    "ec2-user", "centos", "debian", "oracle", "mssql", "sa"
}

is_hardcoded_string(val) {
    val.ir_type == "String"
    count(val.value) > 0
    not startswith(val.value, "${")
    not regex.match("^\\$[A-Z_a-z].*", val.value)
    not regex.match("(?i)^(vault|secretmanager|ssm|kms)\\(.*", val.value)
    not regex.match("^/", val.value)
}

get_name(node) = name {
    node.ir_type == "Variable"
    name := node.name
} else = name {
    node.ir_type == "Attribute"
    name := node.name
} else = name {
    node.key.ir_type == "String"
    name := node.key.value
}

get_element(node) = elem {
    node.ir_type == "Variable"
    elem := node
} else = elem {
    node.ir_type == "Attribute"
    elem := node
} else = elem {
    node.key.ir_type == "String"
    elem := node.key
}

is_high_conf_credential(name) {
    segments := regex.split("[_.\\[\\]'-]+", lower(name))
    segment := segments[_]
    segment == high_conf_credential_names[_]
}

is_user_credential(name) {
    lower_name := lower(name)
    regex.match("^(.*[_.\\[\\]'-])?user(name)?$", lower_name)
}

is_admin_username(val) {
    val.ir_type == "String"
    lower(val.value) == well_known_usernames[_]
}

is_ldap_dn(val) {
    val.ir_type == "String"
    regex.match("(?i)(cn|dc|ou|uid)\\s*=", val.value)
}

is_connection_name(name) {
    segments := regex.split("[_.\\[\\]'-]+", lower(name))
    segment := segments[_]
    segment == connection_names[_]
}

has_embedded_credential(val) {
    val.ir_type == "String"
    regex.match("(?i).*(?:password|passwd|pwd|secret|token)\\s*[=:]\\s*\\S+.*", val.value)
}

is_credential_match(name, val) {
    is_high_conf_credential(name)
    is_hardcoded_string(val)
}

is_credential_match(name, val) {
    is_user_credential(name)
    is_hardcoded_string(val)
    not is_admin_username(val)
    not is_ldap_dn(val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    name := get_name(node)
    is_credential_match(name, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": get_element(node),
        "path": parent.path,
        "description": "Hard-coded credential detected - Credentials should not be embedded directly in code. Use a secrets manager or environment variables instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    name := get_name(node)
    is_high_conf_credential(name)
    val := node.value
    val.ir_type == "String"
    default_weak[_] == lower(val.value)
    result := {
        "type": "sec_hard_secr",
        "element": get_element(node),
        "path": parent.path,
        "description": "Default or weak credential detected - Default and common weak passwords should not be used. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    name := get_name(node)
    is_connection_name(name)
    val := node.value
    has_embedded_credential(val)
    result := {
        "type": "sec_hard_secr",
        "element": get_element(node),
        "path": parent.path,
        "description": "Hard-coded credential found in connection string - Credentials should not be embedded in connection strings. (CWE-798)"
    }
}