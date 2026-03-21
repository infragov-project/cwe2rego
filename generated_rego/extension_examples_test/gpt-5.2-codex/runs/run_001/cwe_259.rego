package glitch

import data.glitch_lib

description := "Hard-coded password or credential found - Secrets should not be embedded in IaC files. (CWE-259)"

is_literal_string(v) {
    v.ir_type == "String"
    not regex.match("(?i).*\\{\\{.*\\}\\}.*", v.value)
    not regex.match("(?i).*\\$\\{.*\\}.*", v.value)
    not regex.match("(?i).*\\$\\(.*\\).*", v.value)
}

is_literal_value(v) {
    is_literal_string(v)
} else {
    v.ir_type == "Integer"
} else {
    v.ir_type == "Float"
} else {
    v.ir_type == "Complex"
}

is_token_count_name(s) {
    regex.match(".*(num|count|number|total)[_-]?tokens?.*", s)
} else {
    regex.match(".*tokens?[_-]?(num|count|number|total).*", s)
}

is_sensitive_name(name) {
    is_string(name)
    s := lower(name)
    regex.match(".*(password|passwd|passphrase|pwd).*", s)
}
is_sensitive_name(name) {
    is_string(name)
    s := lower(name)
    regex.match(".*(secret|credential).*", s)
}
is_sensitive_name(name) {
    is_string(name)
    s := lower(name)
    regex.match(".*(api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|ssh[_-]?key|ftp[_-]?key|smtp[_-]?key|ldap[_-]?key|db[_-]?key|database[_-]?key|auth[_-]?key).*", s)
}
is_sensitive_name(name) {
    is_string(name)
    s := lower(name)
    regex.match("(^|[^a-z0-9])(access|api|auth|secret|client|refresh|session)[_-]?tokens([^a-z0-9]|$)", s)
}
is_sensitive_name(name) {
    is_string(name)
    s := lower(name)
    regex.match("(^|[^a-z0-9])token([^a-z0-9]|$)", s)
    not is_token_count_name(s)
}
is_sensitive_name(name) {
    is_string(name)
    lower(name) == "key"
}

has_embedded_credentials(str) {
    regex.match("(?i).*[^\\s/]+:[^\\s/]+@.*", str)
} else {
    regex.match("(?i).*(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key)=\\S+.*", str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Attribute"
    is_sensitive_name(kv.name)
    is_literal_value(kv.value)

    result := {
        "type": "sec_hard_pass",
        "element": kv,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Variable"
    is_sensitive_name(kv.name)
    is_literal_value(kv.value)

    result := {
        "type": "sec_hard_pass",
        "element": kv,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, entry])
    entry.key
    entry.value
    entry.key.ir_type == "String"
    is_sensitive_name(entry.key.value)
    is_literal_value(entry.value)

    result := {
        "type": "sec_hard_pass",
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
    has_embedded_credentials(s.value)

    result := {
        "type": "sec_hard_pass",
        "element": s,
        "path": parent.path,
        "description": description
    }
}