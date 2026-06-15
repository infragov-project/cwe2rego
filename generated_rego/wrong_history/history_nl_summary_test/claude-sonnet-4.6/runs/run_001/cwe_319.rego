package glitch

import data.glitch_lib

security_false_attrs := {
    "https_only", "enable_https_traffic_only", "enablehttpstrafficonly",
    "secure_transfer_required", "require_ssl", "force_ssl",
    "redirect_http_to_https", "tls_enabled", "ssl_enabled",
    "encrypt_in_transit", "ssl_enforcement_enabled", "require_tls",
    "transit_encryption_enabled", "in_flight_encryption", "hsts_enabled",
    "verify_ssl", "ssl_verify", "verify_certificates", "ssl_redirect",
    "validate_certs"
}

security_true_attrs := {
    "allow_http", "insecure_skip_verify", "skip_ssl_verification",
    "disable_ssl_verification", "tls_skip_verify"
}

cleartext_protocol_attrs := {
    "protocol", "scheme", "listener_protocol", "backend_protocol",
    "endpoint_protocol", "transfer_protocol"
}

cleartext_protocol_values := {"http", "ftp", "telnet", "smtp", "ldap", "tcp"}

ssl_disabled_attrs := {
    "ssl_enforcement", "in_transit_encryption", "encryption_in_transit",
    "transit_encryption", "require_secure_transport", "ssl_mode",
    "sslmode", "client_broker", "insecure_edge_termination_policy"
}

ssl_disabled_values := {"disabled", "disable", "plaintext", "tls_plaintext", "off", "allow"}

weak_tls_attrs := {"minimum_tls_version", "min_protocol_version"}

weak_tls_values := {"tls1_0", "tls1_1", "tlsv1", "tlsv1.1", "1.0", "1.1"}

insecure_ports := {21, 23, 25, 80, 110, 143, 389, 8080, 8000}

is_false_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_false_value(value) {
    value.ir_type == "String"
    lower(value.value) == {"no", "false", "0"}[_]
}

is_true_value(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_true_value(value) {
    value.ir_type == "String"
    lower(value.value) == {"yes", "true", "1"}[_]
}

contains_insecure_url(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)(http|ftp|telnet|ldap)://", node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == security_false_attrs[_]
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Security enforcement attribute disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == security_true_attrs[_]
    is_true_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure transport option explicitly enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == cleartext_protocol_attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == cleartext_protocol_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == ssl_disabled_attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == ssl_disabled_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - TLS/SSL enforcement disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == weak_tls_attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == weak_tls_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak or deprecated TLS version permitted. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"port", "from_port", "to_port"}[_]
    attr.value.ir_type == "Integer"
    attr.value.value == insecure_ports[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure cleartext port exposed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_insecure_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL scheme used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    contains_insecure_url(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL scheme used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == cleartext_protocol_attrs[_]
    entry.value.ir_type == "String"
    lower(entry.value.value) == cleartext_protocol_values[_]
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext protocol configured. (CWE-319)"
    }
}