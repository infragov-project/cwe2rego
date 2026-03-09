package glitch

import data.glitch_lib

insecure_protocol_values := {"HTTP", "FTP", "TELNET", "SMTP", "LDAP", "IMAP", "POP3", "PLAINTEXT"}

protocol_attr_names := {"protocol", "listener_protocol", "connection_protocol", "endpoint_type", "client_broker", "broker_protocol"}

encryption_disable_flags := {"https_only", "enable_https", "enforce_https", "require_https", "https_enabled", "ssl_enabled", "tls_enabled", "enable_ssl", "use_ssl", "transit_encryption_enabled", "encryption_in_transit", "in_transit_encryption", "in_flight_encryption", "secure_transfer", "require_secure_transport", "secure_transfer_required"}

content_has_security_issue(content) {
    regex.match(`(?i)(\b(secure_connection|security_enabled|tls_enabled|ssl_enabled|in_transit_encryption|transit_encryption_enabled|require_ssl|https_only)\s*[=:]\s*(false|no|0|disabled)\b|(tls|ssl)[-_]port\s+0\b|\b(protocol|client_broker)\s*[=:]\s*plaintext\b)`, content)
}

content_line_is_cleartext(line) {
    regex.match(`(?i)(\blisten\s+.*\b(80|21|23|25|110|143|389)\b|VirtualHost[^>]*:(80|21|23|25|110|143|389)\b|\bport\s*[=:]\s*(80|21|23|25|110|143|389)\b)`, line)
}

content_line_is_cleartext(line) {
    regex.match(`(?i)(\b(secure_connection|security_enabled|in_transit_encryption|tls_enabled|ssl_enabled|require_ssl|https_only)\s*[=:]\s*(false|no|0|disabled)\b|\b(protocol|client_broker|broker_protocol)\s*[=:]\s*(plaintext|ftp|telnet|smtp|ldap|imap|pop3)\b|(tls|ssl)[-_]port\s+0\b)`, line)
}

content_line_is_cleartext(line) {
    regex.match(`(?i)(^\s*#.*(disabl|weak).*(tls|ssl|security|encrypt)|(private_key|ssl_key|tls_key)[-_]*(path|file)?\s*[=:])`, line)
}

content_line_in_disabled_context(line) {
    regex.match(`(?i)(^\s*port\s+\d+\b|^\s*bind\s+[0-9.]|\b(hostname|server_name|endpoint)\s*[=:]\s*\S+)`, line)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == protocol_attr_names[_]
    attr.value.ir_type == "String"
    upper(attr.value.value) == insecure_protocol_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol explicitly configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == encryption_disable_flags[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption in transit is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "insecure_skip_verify"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL/TLS certificate verification is bypassed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    attr.value.line >= 1
    lines := split(attr.value.value, "\n")
    some i
    line_text := lines[i]
    content_line_is_cleartext(line_text)
    actual_line := attr.value.line + i
    result := {
        "type": "sec_https",
        "element": {"line": actual_line, "column": 1, "code": line_text, "ir_type": "String", "value": line_text},
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - File content contains insecure configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    attr.value.line >= 1
    content_has_security_issue(attr.value.value)
    lines := split(attr.value.value, "\n")
    some i
    line_text := lines[i]
    content_line_in_disabled_context(line_text)
    actual_line := attr.value.line + i
    result := {
        "type": "sec_https",
        "element": {"line": actual_line, "column": 1, "code": line_text, "ir_type": "String", "value": line_text},
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext configuration in disabled-TLS context. (CWE-319)"
    }
}