package glitch

import data.glitch_lib

https_enforcement_fields := {
    "https_only", "enableHttpsTrafficOnly", "enforce_https",
    "ssl_enforcement_enabled", "require_ssl", "ssl_enabled",
    "tls_enabled", "secure_transfer_required",
    "transit_encryption_enabled", "cookie_secure", "secure_cookie",
    "session_cookie_secure", "redirect_http_to_https"
}

transit_encryption_fields := {
    "encryption_in_transit", "in_transit_encryption", "transit_encryption",
    "ssl_mode", "sslmode"
}

disabled_values := {"disabled", "false", "none", "disable", "no", "off"}

protocol_fields := {"protocol", "listener_protocol", "frontend_protocol", "backend_protocol"}

tls_version_fields := {"minimum_tls_version", "min_tls_version", "tls_version"}

tls_skip_verify_fields := {"insecure_ssl", "skip_ssl_verification", "tls_skip_verify", "no_verify_ssl"}

ssl_verify_fields := {"verify_ssl", "ssl_verify", "certificate_verification", "validate_certs"}

url_name_pattern := "(?i)(url|uri|endpoint|source|src|href|location|download|remote)"

is_false_val(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_false_val(v) {
    v.ir_type == "String"
    lower(v.value) == disabled_values[_]
}

has_http_string(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    startswith(node.value, "http://")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == https_enforcement_fields[_]
    is_false_val(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption enforcement is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == transit_encryption_fields[_]
    is_false_val(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - In-transit encryption is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == protocol_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|smtp|ldap|imap|pop3)$", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure cleartext protocol in use. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_version_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(tls1[._]?0|tls1[._]?1|ssl3|sslv2|sslv3|tlsv1(\\.1)?|1\\.0|1\\.1)$", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak or deprecated TLS/SSL version configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_skip_verify_fields[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - TLS certificate verification is skipped. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ssl_verify_fields[_]
    is_false_val(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS certificate verification is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(url_name_pattern, attr.name)
    has_http_string(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP URL used instead of HTTPS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(url_name_pattern, v.name)
    has_http_string(v.value)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP URL used instead of HTTPS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "Hash"
    entry := v.value.value[_]
    entry.key.ir_type == "String"
    entry.key.value == protocol_fields[_]
    entry.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|smtp|ldap|imap|pop3)$", entry.value.value)

    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure cleartext protocol in Hash config. (CWE-319)"
    }
}