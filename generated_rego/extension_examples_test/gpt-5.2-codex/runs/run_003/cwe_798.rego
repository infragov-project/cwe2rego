package glitch

import data.glitch_lib

desc := "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"

secret_name_patterns := {
    "(?i)(^|[^a-z0-9])pass(word|wd|phrase)?s?[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])pwd[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])secret(s)?[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])token(s)?[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])auth[_-]?token[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])bearer[_-]?token[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])client[_-]?secret[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])access[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])secret[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])api[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])private[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])ssh[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])tls[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])signing[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])encryption[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])shared[_-]?secret[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])shared[_-]?key[0-9]*([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])key_data([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])keystore([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])truststore([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])certificate([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])pem([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])pfx([^a-z0-9]|$)"
}

filelike_name_patterns := {
    "(?i)(^|[^a-z0-9])private[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])ssh[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])tls[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])signing[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])encryption[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])shared[_-]?key([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])key_data([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])keystore([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])truststore([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])certificate([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])pem([^a-z0-9]|$)",
    "(?i)(^|[^a-z0-9])pfx([^a-z0-9]|$)"
}

credential_value_patterns := {
    "(?i)[^\\s:@/]+:[^@/\\s]+@",
    "(?i)(uid|user(name)?|login)\\s*=\\s*[^;\\s]+.*(pass(word)?|pwd)\\s*=\\s*[^;\\s]+",
    "(?i)(pass(word)?|pwd|token|secret|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\\s*[:=]\\s*[^\\s,;]+",
    "(?i)bearer\\s+[A-Za-z0-9._-]+",
    "(?i)(BEGIN\\s+[^\\n]*PRIVATE\\s+KEY|ssh-rsa|ssh-ed25519|-----BEGIN)"
}

allowed_kv_types := {"Variable", "Attribute"}

path_contains_unit_blocks(path) {
    path[_] == "unit_blocks"
}

all_kv(parent) = kvs {
    kvs = {kv |
        walk(parent, [path, kv])
        kv.ir_type == allowed_kv_types[_]
        kv.value.ir_type != "BlockExpr"
        not path_contains_unit_blocks(path)
    }
}

all_hash_entries(parent) = entries {
    entries = {entry |
        walk(parent, [path, h])
        h.ir_type == "Hash"
        not path_contains_unit_blocks(path)
        entry := h.value[_]
    }
}

matches_any_pattern(val, patterns) {
    pattern := patterns[_]
    regex.match(pattern, val)
}

matches_secret_name(name) {
    matches_any_pattern(name, secret_name_patterns)
}

is_filelike_name(name) {
    matches_any_pattern(name, filelike_name_patterns)
}

is_literal_string(v) {
    v.ir_type == "String"
    v.value != ""
    not regex.match(".*\\$\\{.*\\}.*", v.value)
    not regex.match(".*\\{\\{.*\\}\\}.*", v.value)
    not regex.match(".*<%.*%>.*", v.value)
    not regex.match(".*#\\{.*\\}.*", v.value)
    not regex.match(".*%\\{.*\\}.*", v.value)
}

is_file_reference(v) {
    v.ir_type == "String"
    regex.match("^(?:/|\\./|\\.\\./|~/?|[A-Za-z]:\\\\)", v.value)
}

is_file_reference(v) {
    v.ir_type == "String"
    regex.match("(?i).*\\.(pem|pfx|key|crt|cer|jks|p12|p7b|p7c)$", v.value)
}

is_literal_secret_value(v) {
    is_literal_string(v)
}

is_literal_secret_value(v) {
    v.ir_type == "Integer"
}

is_literal_secret_value(v) {
    v.ir_type == "Float"
}

should_flag_by_name(name, v) {
    matches_secret_name(name)
    is_literal_secret_value(v)
    not (is_filelike_name(name) and is_file_reference(v))
}

has_credential_pattern(v) {
    is_literal_string(v)
    matches_any_pattern(v.value, credential_value_patterns)
}

is_credential_kv(kv) {
    should_flag_by_name(kv.name, kv.value)
}

is_credential_kv(kv) {
    not matches_secret_name(kv.name)
    has_credential_pattern(kv.value)
}

is_credential_entry(entry) {
    entry.key.ir_type == "String"
    should_flag_by_name(entry.key.value, entry.value)
}

is_credential_entry(entry) {
    not (entry.key.ir_type == "String" and matches_secret_name(entry.key.value))
    has_credential_pattern(entry.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kv(parent)[_]
    is_credential_kv(kv)

    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": desc
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kv(parent)[_]
    kv.value.ir_type == "Array"
    elem := kv.value.value[_]
    should_flag_by_name(kv.name, elem)

    result := {
        "type": "sec_hard_secr",
        "element": elem,
        "path": parent.path,
        "description": desc
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kv := all_kv(parent)[_]
    kv.value.ir_type == "Array"
    elem := kv.value.value[_]
    has_credential_pattern(elem)

    result := {
        "type": "sec_hard_secr",
        "element": elem,
        "path": parent.path,
        "description": desc
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    entry := all_hash_entries(parent)[_]
    is_credential_entry(entry)

    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": desc
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    entry := all_hash_entries(parent)[_]
    entry.key.ir_type == "String"
    entry.value.ir_type == "Array"
    elem := entry.value.value[_]
    should_flag_by_name(entry.key.value, elem)

    result := {
        "type": "sec_hard_secr",
        "element": elem,
        "path": parent.path,
        "description": desc
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    entry := all_hash_entries(parent)[_]
    entry.value.ir_type == "Array"
    elem := entry.value.value[_]
    has_credential_pattern(elem)

    result := {
        "type": "sec_hard_secr",
        "element": elem,
        "path": parent.path,
        "description": desc
    }
}