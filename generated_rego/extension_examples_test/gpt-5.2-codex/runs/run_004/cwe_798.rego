package glitch

import data.glitch_lib

description := "Use of hard-coded credentials - Avoid embedding authentication material directly in configuration. (CWE-798)"

password_re := "(?i)(^|[^a-z0-9])(pass(word|wd|phrase)?s?|pwd)([^a-z0-9]|$)"
token_re := "(?i)(^|[^a-z0-9])(token|auth_token|bearer|session_key|sas_token)([^a-z0-9]|$)"
secret_re := "(?i)(^|[^a-z0-9])secret(s)?([^a-z0-9]|$)"
key_re := "(?i)(^|[^a-z0-9])((api|access|secret|private|ssh|tls|client)[_-]?key(s)?|key[_-]?(data|pem)|client[_-]?secret)([^a-z0-9]|$)"
store_re := "(?i)(^|[^a-z0-9])(keystore|truststore)([_-]?password)?([^a-z0-9]|$)"
generic_key_re := "(?i)(^|[^a-z0-9])key([^a-z0-9]|$)"

connection_pattern := "(?i)([^\\s:/]+:[^@\\s]+@|\\b(pwd|passwd|password|passphrase|token|secret|apikey|api_key|access_key|secret_key|client_secret|auth_token|bearer|session_key|sas_token)\\s*=\\s*[^\\s'\";]+)"
pem_pattern := "(?s)-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY)-----"

common_users := {"root", "administrator", "admin", "root_user", "admin_user"}

template_string(s) {
    regex.match(".*\\{\\{.*\\}\\}.*", s)
} else {
    regex.match(".*\\$\\{.*\\}.*", s)
} else {
    regex.match(".*<%.*%>.*", s)
} else {
    regex.match(".*#\\{.*\\}.*", s)
}

literal_string(v) {
    v.ir_type == "String"
    v.value != ""
    not template_string(v.value)
}

path_like(s) {
    regex.match("(^/|^[A-Za-z]:\\\\)", s)
} else {
    regex.match(".*[/\\\\].*", s)
} else {
    regex.match("(?i).*\\.(xml|pem|crt|cer|key|jks|p12|pfx|conf|cfg)$", s)
}

secret_file_name(name) {
    regex.match("(?i)secret.*(file|path|dir|xml)", name)
} else {
    regex.match("(?i)(file|path|dir|xml).*secret", name)
}

dn_like(s) {
    regex.match("(?i).*(uid|cn|ou|dc)=.*", s)
}

common_user_value(s) {
    lower(s) == common_users[_]
}

user_name(name) {
    regex.match("(?i)(^|[._-])(user|username|login|account)$", name)
}

has_user_prefix(name) {
    regex.match("(?i)[._-](user|username|login|account)$", name)
}

user_prefix(name) = p {
    has_user_prefix(name)
    p := regex.replace("(?i)[._-](user|username|login|account)$", "", name)
}

sensitive_name(name) {
    regex.match(password_re, name)
} else {
    regex.match(token_re, name)
} else {
    regex.match(secret_re, name)
} else {
    regex.match(key_re, name)
} else {
    regex.match(store_re, name)
}

is_sensitive_field(name, value) {
    sensitive_name(name)
    not (secret_file_name(name) and value.ir_type == "String" and path_like(value.value))
}

user_value_ok(val) {
    literal_string(val)
    not common_user_value(val.value)
    not dn_like(val.value)
}

has_peer_secret(prefix, parent) {
    prefix != ""
    lp := lower(prefix)
    v := parent.variables[_]
    startswith(lower(v.name), lp)
    sensitive_name(v.name)
} else {
    prefix != ""
    lp := lower(prefix)
    a := parent.attributes[_]
    startswith(lower(a.name), lp)
    sensitive_name(a.name)
}

generic_key_name(name) {
    regex.match(generic_key_re, name)
    not sensitive_name(name)
}

auth_context_in_hash(h) {
    e := h.value[_]
    e.key.ir_type == "String"
    sensitive_name(e.key.value)
} else {
    e := h.value[_]
    e.key.ir_type == "String"
    lower(e.key.value) == "method"
    e.value.ir_type == "String"
    lower(e.value.value) == "key"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := parent.variables[_]
    is_sensitive_field(v.name, v.value)
    literal_string(v.value)

    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    is_sensitive_field(attr.name, attr.value)
    literal_string(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    entry.key.ir_type == "String"
    is_sensitive_field(entry.key.value, entry.value)
    literal_string(entry.value)

    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := parent.variables[_]
    user_name(v.name)
    user_value_ok(v.value)
    prefix := user_prefix(v.name)
    has_peer_secret(prefix, parent)

    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "definition"
    attr := parent.attributes[_]
    user_name(attr.name)
    user_value_ok(attr.value)
    has_user_prefix(attr.name)
    prefix := user_prefix(attr.name)
    has_peer_secret(prefix, parent)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "definition"
    attr := parent.attributes[_]
    user_name(attr.name)
    user_value_ok(attr.value)
    not has_user_prefix(attr.name)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    auth_context_in_hash(h)
    entry := h.value[_]
    entry.key.ir_type == "String"
    generic_key_name(entry.key.value)
    literal_string(entry.value)

    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, s])
    s.ir_type == "String"
    not template_string(s.value)
    regex.match(connection_pattern, s.value)

    result := {
        "type": "sec_hard_secr",
        "element": s,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, s])
    s.ir_type == "String"
    not template_string(s.value)
    regex.match(pem_pattern, s.value)

    result := {
        "type": "sec_hard_secr",
        "element": s,
        "path": parent.path,
        "description": description
    }
}