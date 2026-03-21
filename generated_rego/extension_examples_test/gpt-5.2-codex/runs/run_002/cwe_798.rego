package glitch

import data.glitch_lib

description := "Use of hard-coded credentials - Avoid embedding static secrets in IaC definitions. (CWE-798)"

strong_key_re := "(?i)(password|passwd|pwd|passphrase|secret(_?key)?|access[_-]?key|api[_-]?key|client[_-]?secret|private[_-]?key|ssh[_-]?key|signature[_-]?key|shared[_-]?key|encryption[_-]?key|key[_-]?material|key[_-]?data|keystore|truststore|certificate|cert|pem|keytab)"
token_key_re := "(?i)(^|[^a-z0-9])token(s)?([^a-z0-9]|$)"
user_key_re := "(?i)(^|[^a-z0-9])(user(name)?|service[_-]?account)([^a-z0-9]|$)"
auth_context_re := "(?i)(auth|credential|login|password|secret|token)"

cred_uri_pattern := "(?i).*://[^/@:]+:[^/@]+@[^\\s]+.*"
cred_assign_pattern := "(?i).*(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\\s*[:=]\\s*[^\\s]+.*"
pem_pattern := "(?i).*-----BEGIN (?:RSA |DSA |EC |OPENSSH |)?PRIVATE KEY-----.*"
cert_pattern := "(?i).*-----BEGIN CERTIFICATE-----.*"
ssh_pattern := "(?i)^ssh-(rsa|ed25519)\\s+[A-Za-z0-9+/]+=*$"
auth_header_pattern := "(?i)^(Bearer|Basic)\\s+[A-Za-z0-9+/=._-]+$"

value_is_primitive(val) {
    val.ir_type == "String"
    val.value != ""
}
value_is_primitive(val) {
    val.ir_type == "Integer"
}
value_is_primitive(val) {
    val.ir_type == "Float"
}

value_is_array_of_primitives(val) {
    val.ir_type == "Array"
    elem := val.value[_]
    value_is_primitive(elem)
}

value_is_literal(val) {
    value_is_primitive(val)
}
value_is_literal(val) {
    value_is_array_of_primitives(val)
}

value_is_string_like(val) {
    val.ir_type == "String"
    val.value != ""
}
value_is_string_like(val) {
    val.ir_type == "Array"
    elem := val.value[_]
    elem.ir_type == "String"
    elem.value != ""
}

sensitive_name_with_value(name, val) {
    n := lower(name)
    regex.match(strong_key_re, n)
    value_is_literal(val)
}
sensitive_name_with_value(name, val) {
    n := lower(name)
    regex.match(user_key_re, n)
    value_is_string_like(val)
}
sensitive_name_with_value(name, val) {
    n := lower(name)
    regex.match(token_key_re, n)
    value_is_string_like(val)
}

auth_context_hash(h, root) {
    kv := h.value[_]
    kv.key.ir_type == "String"
    regex.match(auth_context_re, lower(kv.key.value))
}
auth_context_hash(h, root) {
    kv := h.value[_]
    kv.key.ir_type == "String"
    lower(kv.key.value) == "method"
    kv.value.ir_type == "String"
    regex.match("(?i)(key|token|password|secret)", kv.value.value)
}
auth_context_hash(h, root) {
    walk(root, [_, kv])
    kv.value == h
    kv.key.ir_type == "String"
    regex.match(auth_context_re, lower(kv.key.value))
}
auth_context_hash(h, root) {
    walk(root, [_, v])
    glitch_lib.is_ir_type_in(v, {"Variable", "Attribute"})
    v.value == h
    regex.match(auth_context_re, lower(v.name))
}

string_has_cred_pattern(s) {
    regex.match(cred_uri_pattern, s)
}
string_has_cred_pattern(s) {
    regex.match(cred_assign_pattern, s)
}
string_has_cred_pattern(s) {
    regex.match(pem_pattern, s)
}
string_has_cred_pattern(s) {
    regex.match(cert_pattern, s)
}
string_has_cred_pattern(s) {
    regex.match(ssh_pattern, s)
}
string_has_cred_pattern(s) {
    regex.match(auth_header_pattern, s)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    sensitive_name_with_value(v.name, v.value)

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
    sensitive_name_with_value(attr.name, attr.value)

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
    walk(parent, [_, kv])
    kv.key.ir_type == "String"
    sensitive_name_with_value(kv.key.value, kv.value)

    result := {
        "type": "sec_hard_secr",
        "element": kv.value,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    auth_context_hash(h, parent)
    kv := h.value[_]
    kv.key.ir_type == "String"
    lower(kv.key.value) == "key"
    value_is_literal(kv.value)

    result := {
        "type": "sec_hard_secr",
        "element": kv.value,
        "path": parent.path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, s])
    s.ir_type == "String"
    string_has_cred_pattern(s.value)

    result := {
        "type": "sec_hard_secr",
        "element": s,
        "path": parent.path,
        "description": description
    }
}