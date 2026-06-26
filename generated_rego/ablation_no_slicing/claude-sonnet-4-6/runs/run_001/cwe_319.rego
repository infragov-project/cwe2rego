package glitch

import data.glitch_lib

encryption_should_be_true_attrs := {
    "https_only", "enable_https", "supportshttpstrafficonly",
    "enablehttpstrafficonly", "require_secure_transfer",
    "secure_transfer_required", "https_traffic_only", "enforce_https",
    "redirect_http_to_https", "http_to_https_redirect", "force_https",
    "transit_encryption_enabled", "in_transit_encryption",
    "encrypt_in_transit", "enable_tls", "in_flight_encryption",
    "transport_encryption", "ssl_enabled", "tls_enabled",
    "ssl_enforcement_enabled", "require_ssl", "ssl_required",
    "enforce_ssl", "verify_ssl", "verify_tls", "ssl_verify",
    "validate_certs"
}

insecure_flag_attrs := {
    "insecure_skip_verify", "insecure", "disable_ssl_validation", "allow_http"
}

protocol_field_names := {
    "protocol", "listener_protocol", "backend_protocol", "frontend_protocol"
}

cleartext_protocol_values := {"http", "ftp", "ldap", "telnet", "smtp"}

weak_tls_versions := {"tls1_0", "tls1_1", "sslv3", "tlsv1", "1.0", "1.1"}

ssl_mode_attrs := {"ssl_mode", "sslmode"}

non_enforcing_ssl_modes := {"disable", "allow", "prefer"}

has_cleartext_url(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^(http|ftp|ldap|telnet|smtp)://", n.value)
}

is_falsy_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_falsy_value(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

is_falsy_value(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_falsy_value(value) {
    value.ir_type == "String"
    lower(value.value) == "disabled"
}

is_falsy_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_truthy_string(value) {
    value.ir_type == "String"
    lower(value.value) == "yes"
}

is_truthy_string(value) {
    value.ir_type == "String"
    lower(value.value) == "true"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == encryption_should_be_true_attrs[_]
    is_falsy_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption or HTTPS enforcement is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == insecure_flag_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure connection flag is enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == insecure_flag_attrs[_]
    is_truthy_string(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure connection flag is enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "minimum_tls_version"
    attr.value.ir_type == "String"
    lower(attr.value.value) == weak_tls_versions[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak TLS version is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == protocol_field_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == cleartext_protocol_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext protocol is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    has_cleartext_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext URL scheme is used. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == ssl_mode_attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == non_enforcing_ssl_modes[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Non-enforcing SSL mode is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    has_cleartext_url(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext URL scheme is used in variable. (CWE-319)"
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
    lower(entry.key.value) == protocol_field_names[_]
    entry.value.ir_type == "String"
    lower(entry.value.value) == cleartext_protocol_values[_]
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cleartext protocol is configured in nested variable. (CWE-319)"
    }
}