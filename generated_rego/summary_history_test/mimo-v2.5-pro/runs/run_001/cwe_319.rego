package glitch

import data.glitch_lib
import future.keywords.in

glitch_insecure_protocols := {
    "http", "ftp", "telnet", "rlogin", "smtp",
    "pop3", "imap", "snmp", "jdbc", "mongodb",
    "mysql", "postgres", "redis", "amqp", "mqtt"
}

glitch_protocol_keys := {
    "protocol", "scheme", "transport",
    "endpoint_protocol", "connection_protocol", "uri_scheme"
}

glitch_encryption_attrs := {
    "use_ssl", "ssl_enforced", "encryption_enabled", "ssl", "tls",
    "https_only", "enforce_https", "secure", "secure_channel",
    "transport_encryption", "require_secure_transport",
    "enable_https_traffic_only", "supports_https_traffic_only",
    "encrypt", "sslmode", "ssl_mode",
    "validate_certs", "verify_ssl", "verify"
}

glitch_insecure_flag_attrs := {
    "insecure", "no_verify", "no_ssl", "nossl", "skip_tls_verify"
}

glitch_false_strings := {"false", "disabled", "off", "0", "no", "none"}
glitch_true_strings := {"true", "yes", "on", "1"}

glitch_is_insecure_protocol_uri(str) {
    some p in glitch_insecure_protocols
    regex.match(sprintf("(?i)%s://", [p]), str)
}

glitch_is_bare_insecure_protocol(str) {
    lower(str) in glitch_insecure_protocols
}

glitch_is_false_value(v) {
    v.ir_type == "String"
    lower(v.value) in glitch_false_strings
} else {
    v.ir_type == "Boolean"
    v.value == false
} else {
    v.ir_type == "Integer"
    v.value == 0
}

glitch_is_true_value(v) {
    v.ir_type == "String"
    lower(v.value) in glitch_true_strings
} else {
    v.ir_type == "Boolean"
    v.value == true
} else {
    v.ir_type == "Integer"
    v.value == 1
}

glitch_is_kv_type(node) {
    node.ir_type == "Attribute"
} else {
    node.ir_type == "Variable"
}

glitch_kv_is_insecure(node) {
    lower(node.name) in glitch_encryption_attrs
    glitch_is_false_value(node.value)
} else {
    lower(node.name) in glitch_insecure_flag_attrs
    glitch_is_true_value(node.value)
}

glitch_hash_entry_is_encryption_insecure(entry) {
    lower(entry.key.value) in glitch_encryption_attrs
    glitch_is_false_value(entry.value)
} else {
    lower(entry.key.value) in glitch_insecure_flag_attrs
    glitch_is_true_value(entry.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    node.value != ""
    glitch_is_insecure_protocol_uri(node.value)
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Potential cleartext transmission of sensitive information - Insecure protocol URI detected. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) in glitch_protocol_keys
    entry.value.ir_type == "String"
    glitch_is_bare_insecure_protocol(entry.value.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Potential cleartext transmission of sensitive information - Insecure protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    glitch_is_kv_type(node)
    lower(node.name) in glitch_protocol_keys
    node.value.ir_type == "String"
    glitch_is_bare_insecure_protocol(node.value.value)
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Potential cleartext transmission of sensitive information - Insecure protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    glitch_is_kv_type(node)
    glitch_kv_is_insecure(node)
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Potential cleartext transmission of sensitive information - Encryption explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    glitch_hash_entry_is_encryption_insecure(entry)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Potential cleartext transmission of sensitive information - Encryption explicitly disabled. (CWE-319)"
    }
}