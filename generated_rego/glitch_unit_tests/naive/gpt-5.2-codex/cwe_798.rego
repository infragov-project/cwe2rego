package glitch

import data.glitch_lib

credential_keywords := {
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "api_key",
    "access_key",
    "secret_key",
    "secret",
    "token",
    "auth_token",
    "bearer_token",
    "session_token",
    "refresh_token",
    "client_secret",
    "app_secret",
    "shared_secret",
    "credential",
    "authentication",
    "auth",
    "private_key",
    "ssh_key",
    "tls_key",
    "client_key",
    "encryption_key",
    "master_key",
    "shared_key",
    "key_data",
    "key_material"
}

username_keywords := {
    "user",
    "username",
    "login",
    "account"
}

default_users := {
    "root",
    "admin",
    "administrator",
    "superuser",
    "service"
}

is_credential_name(name) {
    kw := credential_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), name)
}

is_username_name(name) {
    kw := username_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), name)
}

is_default_user(str) {
    du := default_users[_]
    regex.match(sprintf("(?i)^%s$", [du]), str)
}

is_plain_string(str) {
    not regex.match(".*\\$\\{[^}]+\\}.*", str)
    not regex.match(".*\\{\\{[^}]+\\}\\}.*", str)
    not regex.match(".*\\#\\{[^}]+\\}.*", str)
    not regex.match("^\\$[A-Za-z_][A-Za-z0-9_]*$", str)
}

is_literal_value(val) {
    val.ir_type == "String"
    is_plain_string(val.value)
}

is_literal_value(val) {
    val.ir_type == "Integer"
}

is_literal_value(val) {
    val.ir_type == "Float"
}

has_connection_credentials(str) {
    regex.match("(?i).*[^/:]+:[^@]+@.*", str)
}

has_connection_credentials(str) {
    regex.match("(?i).*password=.*", str)
}

has_connection_credentials(str) {
    regex.match("(?i).*pwd=.*", str)
}

has_connection_credentials(str) {
    regex.match("(?i).*user=.*", str)
}

has_connection_credentials(str) {
    regex.match("(?i).*uid=.*", str)
}

has_private_key(str) {
    regex.match("(?i).*BEGIN [A-Z ]*PRIVATE KEY.*", str)
}

has_private_key(str) {
    regex.match("(?i).*PRIVATE KEY-----.*", str)
}

has_private_key(str) {
    regex.match("(?i).*ssh-rsa.*", str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_name(attr.name)
    is_literal_value(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_credential_name(v.name)
    is_literal_value(v.value)

    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    pair := h.value[_]
    key := pair.key
    val := pair.value
    key.ir_type == "String"
    is_credential_name(key.value)
    is_literal_value(val)

    result := {
        "type": "sec_hard_secr",
        "element": val,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_username_name(attr.name)
    attr.value.ir_type == "String"
    is_plain_string(attr.value.value)
    is_default_user(attr.value.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_username_name(v.name)
    v.value.ir_type == "String"
    is_plain_string(v.value.value)
    is_default_user(v.value.value)

    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    pair := h.value[_]
    key := pair.key
    val := pair.value
    key.ir_type == "String"
    is_username_name(key.value)
    val.ir_type == "String"
    is_plain_string(val.value)
    is_default_user(val.value)

    result := {
        "type": "sec_hard_secr",
        "element": val,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    p := h.value[_]
    p.key.ir_type == "String"
    is_credential_name(p.key.value)
    is_literal_value(p.value)
    u := h.value[_]
    u.key.ir_type == "String"
    is_username_name(u.key.value)
    is_literal_value(u.value)

    result := {
        "type": "sec_hard_secr",
        "element": u.value,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, s])
    s.ir_type == "String"
    is_plain_string(s.value)
    has_connection_credentials(s.value)

    result := {
        "type": "sec_hard_secr",
        "element": s,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, s])
    s.ir_type == "String"
    is_plain_string(s.value)
    has_private_key(s.value)

    result := {
        "type": "sec_hard_secr",
        "element": s,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding credentials directly in IaC definitions. (CWE-798)"
    }
}