package glitch

import data.glitch_lib

cred_patterns := {
    "(?i)(^|[^a-z0-9])(password|passwd|pwd|passphrase)([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])secret([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])token([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])api[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])access[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])secret[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])client[_-]?secret([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])app[_-]?secret([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])shared[_-]?secret([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])bearer[_-]?token([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])auth[_-]?token([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])access[_-]?token([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])service[_-]?account[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])client[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])private[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])ssh[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])tls[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])encryption[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])master[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])vault[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])key[_-]?password([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])keystore[_-]?password([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])truststore[_-]?password([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])authorization([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])basic[_-]?auth([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])jwt([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])admin[_-]?user([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])admin[_-]?password([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])root[_-]?password([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])bootstrap[_-]?password([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])default[_-]?password([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])initial[_-]?password([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])superuser([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])maintenance[_-]?user([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])diagnostic[_-]?user([^a-z0-9]|$)"
}

store_patterns := {
    "(?i)(^|[^a-z0-9])keystore([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])truststore([^a-z0-9]|$)"
}

cert_patterns := {
    "(?i)(^|[^a-z0-9])cert(ificate)?([^a-z0-9]|$)"
}

conn_patterns := {
    "(?i)[^/\\s:@]+:[^/\\s@]+@",
    "(?i)(user(name)?|uid)\\s*=\\s*[^;\\s]+;\\s*(password|pwd)\\s*=\\s*[^;\\s]+",
    "(?i)(password|pwd)\\s*=\\s*[^;\\s&]+"
}

user_tokens := {"user", "username", "login", "account", "uid", "admin", "root", "superuser"}

matches_any(patterns, name) {
    p := patterns[_]
    regex.match(p, name)
}

is_literal(v) {
    v.ir_type == "String"
}
is_literal(v) {
    v.ir_type == "Integer"
}
is_literal(v) {
    v.ir_type == "Float"
}

name_tokens(name) = ts {
    ts := regex.find_n("[A-Za-z0-9]+", lower(name), -1)
}

last_token(name) = tok {
    ts := name_tokens(name)
    count(ts) > 0
    idx := count(ts) - 1
    tok := ts[idx]
}

prefix_tokens(name) = p {
    ts := name_tokens(name)
    count(ts) > 1
    p := [t | some i; t := ts[i]; i < count(ts)-1]
}

same_prefix(n1, n2) {
    p1 := prefix_tokens(n1)
    p2 := prefix_tokens(n2)
    p1 == p2
}

is_user_key(name) {
    t := last_token(name)
    user_tokens[t]
}

credential_key_name(name) {
    matches_any(cred_patterns, name)
}
credential_key_name(name) {
    matches_any(store_patterns, name)
}
credential_key_name(name) {
    matches_any(cert_patterns, name)
    not is_ca_cert_name(name)
}

is_ca_cert_name(name) {
    regex.match("(?i).*ca[^a-z0-9]*cert.*", name)
}
is_ca_cert_name(name) {
    regex.match("(?i).*cacert.*", name)
}
is_ca_cert_name(name) {
    regex.match("(?i).*ca[_-]?bundle.*", name)
}
is_ca_cert_name(name) {
    regex.match("(?i).*ca[_-]?trust.*", name)
}

connection_cred(val) {
    val.ir_type == "String"
    p := conn_patterns[_]
    regex.match(p, val.value)
}

has_companion_cred(name, parent) {
    other := glitch_lib.all_variables(parent)[_]
    other.name != name
    same_prefix(name, other.name)
    credential_key_name(other.name)
    is_literal(other.value)
}
has_companion_cred(name, parent) {
    other := glitch_lib.all_attributes(parent)[_]
    other.name != name
    same_prefix(name, other.name)
    credential_key_name(other.name)
    is_literal(other.value)
}

hash_has_cred(h) {
    p := h.value[_]
    p.key.ir_type == "String"
    credential_key_name(p.key.value)
    is_literal(p.value)
}

sensitive_kv(kv, parent) {
    credential_key_name(kv.name)
    is_literal(kv.value)
}
sensitive_kv(kv, parent) {
    is_user_key(kv.name)
    is_literal(kv.value)
    has_companion_cred(kv.name, parent)
}
sensitive_kv(kv, parent) {
    connection_cred(kv.value)
}

sensitive_pair(key, val, h) {
    credential_key_name(key)
    is_literal(val)
}
sensitive_pair(key, val, h) {
    is_user_key(key)
    is_literal(val)
    hash_has_cred(h)
}
sensitive_pair(key, val, h) {
    connection_cred(val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := glitch_lib.all_variables(parent)[_]
    sensitive_kv(kv, parent)
    result := {
        "type": "sec_hard_secr",
        "element": kv.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := glitch_lib.all_attributes(parent)[_]
    sensitive_kv(kv, parent)
    result := {
        "type": "sec_hard_secr",
        "element": kv.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    p := h.value[_]
    p.key.ir_type == "String"
    key := p.key.value
    val := p.value
    sensitive_pair(key, val, h)
    result := {
        "type": "sec_hard_secr",
        "element": val,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC. (CWE-798)"
    }
}