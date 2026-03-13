package glitch

import data.glitch_lib

encryption_disabled_pattern := "(?i)^(enable_ssl|ssl_enabled|tls_enabled|https_only|enable_https_traffic_only|require_ssl|require_secure_transfer|secure_transfer_required|enforce_https|in_transit_encryption_enabled|verify_ssl|redirect_https|redirect_http_to_https)$"

bypass_enabled_pattern := "(?i)^(tls_skip_verify|insecure_skip_verify|skip_ssl_validation|allow_unencrypted_connections)$"

weak_tls_versions := {"TLS1_0", "TLS1_1", "TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"}

is_false_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_false_value(value) {
    value.ir_type == "VariableReference"
    lower(value.value) == "false"
}

is_false_value(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_true_value(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_true_value(value) {
    value.ir_type == "VariableReference"
    lower(value.value) == "true"
}

is_true_value(value) {
    value.ir_type == "String"
    lower(value.value) == "true"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(encryption_disabled_pattern, attr.name)
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption in transit is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(bypass_enabled_pattern, attr.name)
    is_true_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - TLS/SSL verification is bypassed or unencrypted connections are explicitly allowed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(ssl_enforcement|encryption_in_transit|transit_encryption)", attr.name)
    attr.value.ir_type == "String"
    lower(attr.value.value) == "disabled"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL enforcement or encryption is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(minimum_tls_version|tls_version)$", attr.name)
    attr.value.ir_type == "String"
    attr.value.value == weak_tls_versions[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak or deprecated TLS version is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap)://", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure protocol scheme found in configuration value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(protocol|scheme)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap|smtp|imap|pop3)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure plaintext protocol is configured. (CWE-319)"
    }
}