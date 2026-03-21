package glitch

import data.glitch_lib

sensitive_pattern := "(?i)(^|[^a-z0-9])(password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|bearer|private[_-]?key|ssh[_-]?key|tls[_-]?key|key_data|encryption[_-]?key|credential|keystore|truststore)([^a-z0-9]|$)"

cred_assign_pattern := "(?i)(password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|bearer|private[_-]?key|ssh[_-]?key|tls[_-]?key|key_data|encryption[_-]?key)\\s*[:=]\\s*[^\\s\"']+"
uri_cred_pattern := "(?i)\\w+://[^\\s:@]+:[^\\s@]+@"
conn_string_pattern := "(?i)(user|uid|username)=[^;\\s]+;\\s*(password|pwd)=[^;\\s]+"

is_placeholder(s) {
    regex.match(".*\\$\\{.*\\}.*", s)
} else {
    regex.match(".*\\{\\{.*\\}\\}.*", s)
}

is_secret_string(v) {
    v.ir_type == "String"
    v.value != ""
    not is_placeholder(v.value)
}

is_secret_value(v) {
    is_secret_string(v)
} else {
    v.ir_type == "Array"
    some e
    e := v.value[_]
    is_secret_string(e)
} else {
    v.ir_type == "Hash"
    some kv
    kv := v.value[_]
    is_secret_string(kv.value)
}

sensitive_name(name) {
    regex.match(sensitive_pattern, name)
}

auth_context(h) {
    some e
    e := h.value[_]
    e.key.ir_type == "String"
    k := lower(e.key.value)
    allowed := {"method", "type"}
    k == allowed[_]
    e.value.ir_type == "String"
    regex.match("(?i)(key|password|token|secret)", e.value.value)
} else {
    some e
    e := h.value[_]
    e.key.ir_type == "String"
    regex.match("(?i)(auth|authentication|credential|login|password|secret|token)", e.key.value)
}

key_entry_secret(entry, h) {
    entry.key.ir_type == "String"
    lower(entry.key.value) == "key"
    is_secret_string(entry.value)
    auth_context(h)
}

string_has_cred(s) {
    regex.match(cred_assign_pattern, s)
} else {
    regex.match(uri_cred_pattern, s)
} else {
    regex.match(conn_string_pattern, s)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    sensitive_name(v.name)
    is_secret_value(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding secrets directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    a := glitch_lib.all_attributes(parent)[_]
    sensitive_name(a.name)
    is_secret_value(a.value)
    result := {
        "type": "sec_hard_secr",
        "element": a,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding secrets directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    entry.key.ir_type == "String"
    sensitive_name(entry.key.value)
    is_secret_value(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding secrets directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    key_entry_secret(entry, h)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding secrets directly in IaC definitions. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, s])
    s.ir_type == "String"
    is_secret_string(s)
    string_has_cred(s.value)
    result := {
        "type": "sec_hard_secr",
        "element": s,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid embedding secrets directly in IaC definitions. (CWE-798)"
    }
}