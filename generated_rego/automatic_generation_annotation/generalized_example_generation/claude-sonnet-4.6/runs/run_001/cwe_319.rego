package glitch

import data.glitch_lib

ssl_flags := {
    "ssl", "ssl_enabled", "https_only", "tls_enabled", "require_ssl",
    "ssl_enforcement_enabled", "enforce_ssl", "transit_encryption_enabled",
    "secure_transfer_required", "in_transit_encryption_enabled",
    "secure_transfer_enabled", "enable_https_traffic_only",
    "redirect_http_to_https", "force_https", "require_secure_transport",
    "ssl_connection", "ssl_verify", "verify_ssl", "validate_certs",
    "sslverify", "check_hostname", "cookie_secure", "session_cookie_secure"
}

skip_verify_flags := {
    "insecure_skip_verify", "tls_skip_verify", "disable_ssl_verification"
}

insecure_ports_int := {80, 21, 23, 25, 389, 8080, 8008}
insecure_ports_str := {"80", "21", "23", "25", "389", "8080", "8008"}

is_falsy(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_falsy(value) {
    value.ir_type == "String"
    regex.match("(?i)^(false|no|0|disabled)$", value.value)
}

is_falsy(value) {
    value.ir_type == "VariableReference"
    regex.match("(?i)^(false|no|0|disabled)$", value.value)
}

is_truthy(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_truthy(value) {
    value.ir_type == "String"
    regex.match("(?i)^(true|yes|1)$", value.value)
}

is_truthy(value) {
    value.ir_type == "VariableReference"
    regex.match("(?i)^(true|yes|1)$", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    ssl_flags[attr.name]
    is_falsy(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption or verification flag is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    skip_verify_flags[attr.name]
    is_truthy(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS verification is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(http|ftp|telnet|ldap|smtp|ws)://", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol in value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(ssl_enabled|https_only|tls_enabled|require_ssl|enforce_ssl|validate_certs|sslverify|transit_encryption|secure_transfer)\\s*[=:]\\s*(false|no|0|disabled)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Configuration disables SSL/TLS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(port|listen|bind)", attr.name)
    attr.value.ir_type == "Integer"
    insecure_ports_int[attr.value.value]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure port configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(port|listen|bind)", attr.name)
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    insecure_ports_str[elem.value]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure port in array value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "ssl_mode"
    attr.value.ir_type == "String"
    regex.match("(?i)^(disable|disabled|allow|prefer)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL mode not enforcing encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "min_tls_version"
    attr.value.ir_type == "String"
    regex.match("(?i)^(SSLv[23]|TLS(v)?1[._]?[01])$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak or deprecated TLS/SSL version. (CWE-319)"
    }
}