package glitch

import data.glitch_lib

cleartext_protocol_url_pattern := "(?i)^(http|ftp|telnet|smtp|ldap)://"

protocol_attr_names := {"protocol", "listener_protocol", "frontend_protocol", "backend_protocol", "scheme"}

cleartext_protocol_values := {"http", "ftp", "telnet", "smtp", "ldap"}

false_disables_encryption := {
    "ssl_enabled", "tls_enabled", "https_only", "require_ssl",
    "enable_https_traffic_only", "transit_encryption_enabled",
    "secure_transfer_required", "enable_secure_transfer", "enforce_https",
    "ssl_verification", "secure", "cookie_secure", "session_cookie_secure"
}

ssl_mode_attr_names := {"ssl_mode", "sslmode", "ssl_enforcement"}

weak_tls_version_values := {"TLS1_0", "TLS1_1", "1.0", "1.1", "TLSv1", "TLSv1.1", "SSLv3"}

tls_version_attr_names := {"min_tls_version", "minimum_tls_version", "minimum_protocol_version"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(cleartext_protocol_url_pattern, attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted protocol URL used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == protocol_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(sprintf("(?i)^(%s)$", [concat("|", cleartext_protocol_values)]), attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext protocol configured in listener or endpoint. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == false_disables_encryption[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption or security flag explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "insecure_skip_verify"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS certificate verification disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ssl_mode_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(disable|disabled)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS mode explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_version_attr_names[_]
    attr.value.ir_type == "String"
    attr.value.value == weak_tls_version_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak TLS version configured below 1.2. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "viewer_protocol_policy"
    attr.value.ir_type == "String"
    regex.match("(?i)^(allow-all|http-only)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Viewer protocol policy allows unencrypted HTTP traffic. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(Encrypt=False|sslmode=disable|sslmode=disabled|ssl=false)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Connection string contains disabled encryption setting. (CWE-319)"
    }
}