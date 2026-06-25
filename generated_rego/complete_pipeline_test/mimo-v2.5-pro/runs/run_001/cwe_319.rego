package glitch

import data.glitch_lib

cleartext_protocols := {"http://", "ftp://", "telnet://", "redis://", "amqp://", "mqtt://", "memcached://", "smtp://"}

false_like_values := {"false", "disabled", "no", "0", "off"}

insecure_tls_versions := {"ssl2", "ssl3", "sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "tls1.0", "tls1.1", "tls1_0", "tls1_1", "tlsv1_0", "tlsv1_1"}

endpoint_attr_names := {"endpoint", "scheme", "url", "address", "connection_string", "source", "location", "base_url", "host"}

security_flag_names := {"enable_https_traffic_only", "secure_transfer", "enforce_ssl", "require_encryption", "use_ssl", "encrypted", "ssl", "tls", "validate_certs", "verify"}

tls_attr_names := {"min_tls_version", "ssl_policy", "protocol_version", "cipher_suite", "min_tls", "tls_version"}

insecure_value_keywords := {"plaintext", "cleartext", "unsecured", "nossl", "notls"}

cleartext_context_values := {"http", "ftp", "telnet", "redis", "amqp", "mqtt", "memcached", "smtp"}

protocol_attrs := {"protocol", "scheme", "transport", "endpoint", "listener_protocol", "frontend_protocol"}

is_cleartext_value(v) {
    lower_v := lower(v)
    cleartext_protocols[p]
    contains(lower_v, p)
}

is_insecure_keyword_value(v) {
    lower_v := lower(v)
    insecure_value_keywords[k]
    contains(lower_v, k)
}

is_false_like(v) {
    v.ir_type == "Boolean"
    v.value == false
} else {
    v.ir_type == "String"
    false_like_values[lower(v.value)]
} else {
    v.ir_type == "Integer"
    v.value == 0
}

is_insecure_tls(v) {
    v.ir_type == "String"
    insecure_tls_versions[lower(v.value)]
}

has_cleartext_in_ast(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    is_cleartext_value(n.value)
}

has_insecure_keyword_in_ast(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    is_insecure_keyword_value(n.value)
}

has_insecure_tls_in_ast(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    insecure_tls_versions[lower(n.value)]
}

has_cleartext_context_in_ast(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    cleartext_context_values[lower(n.value)]
}

contains_cleartext_protocol(v) {
    v.ir_type == "String"
    is_cleartext_value(v.value)
} else {
    has_cleartext_in_ast(v)
}

check_hash_entry(entry) {
    entry.key.ir_type == "String"
    endpoint_attr_names[lower(entry.key.value)]
    contains_cleartext_protocol(entry.value)
}

check_hash_entry(entry) {
    entry.key.ir_type == "String"
    has_insecure_keyword_in_ast(entry.value)
}

check_hash_entry(entry) {
    entry.key.ir_type == "String"
    protocol_attrs[lower(entry.key.value)]
    has_cleartext_context_in_ast(entry.value)
}

check_hash_entry(entry) {
    entry.key.ir_type == "String"
    security_flag_names[lower(entry.key.value)]
    is_false_like(entry.value)
}

check_hash_entry(entry) {
    entry.key.ir_type == "String"
    tls_attr_names[lower(entry.key.value)]
    is_insecure_tls(entry.value)
}

check_hash_entry(entry) {
    entry.key.ir_type == "String"
    tls_attr_names[lower(entry.key.value)]
    has_insecure_tls_in_ast(entry.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    endpoint_attr_names[lower(attr.name)]
    contains_cleartext_protocol(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext protocol used for potentially sensitive data transmission - Use encrypted protocols such as HTTPS, SFTP, or SSH. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    security_flag_names[lower(attr.name)]
    is_false_like(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption or TLS enforcement explicitly disabled - Enable encryption for data in transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    tls_attr_names[lower(attr.name)]
    is_insecure_tls(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure TLS/SSL version configured - Use TLS 1.2 or higher. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    check_hash_entry(entry)
    result := {
        "type": "sec_https",
        "element": entry.key,
        "path": parent.path,
        "description": "Cleartext protocol or disabled encryption found in nested configuration - Use encrypted protocols for sensitive data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    contains_cleartext_protocol(variable.value)
    result := {
        "type": "sec_https",
        "element": variable,
        "path": parent.path,
        "description": "Variable contains cleartext protocol reference for potentially sensitive data - Use encrypted protocols. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    variable.value.ir_type == "Hash"
    entry := variable.value.value[_]
    check_hash_entry(entry)
    result := {
        "type": "sec_https",
        "element": entry.key,
        "path": parent.path,
        "description": "Variable hash contains cleartext protocol or disabled encryption setting - Use encrypted protocols for sensitive data transmission. (CWE-319)"
    }
}