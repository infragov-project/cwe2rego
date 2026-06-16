package glitch

import data.glitch_lib

insecure_when_false_attrs := {
    "https_only", "enable_https_traffic_only", "require_ssl",
    "ssl_required", "tls_enabled", "ssl_enabled", "enforce_https",
    "secure_transfer_enabled", "transit_encryption_enabled",
    "in_transit_encryption_enabled", "ssl_verify", "verify_ssl",
    "secure", "validate_certs"
}

insecure_when_true_attrs := {
    "insecure_skip_verify", "tls_skip_verify"
}

insecure_transmission_string_attrs := {
    "ssl_mode", "encryption_in_transit", "require_secure_transport",
    "transit_encryption"
}

insecure_transmission_string_values := {"disable", "disabled", "none", "off"}

weak_tls_version_values := {"tls1_0", "tls1_1", "sslv3", "tlsv1", "ssl3", "tls1.0", "tls1.1", "tlsv1.1"}

insecure_cleartext_protocols := {"http", "ftp", "telnet", "smtp"}

is_falsy(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_falsy(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

is_falsy(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_truthy(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_truthy(value) {
    value.ir_type == "String"
    lower(value.value) == "yes"
}

is_truthy(value) {
    value.ir_type == "String"
    lower(value.value) == "true"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == insecure_when_false_attrs[_]
    is_falsy(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTPS/TLS enforcement is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == insecure_when_true_attrs[_]
    is_truthy(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS certificate verification is bypassed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)://", node.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted protocol used in URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)://", node.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Unencrypted protocol used in URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*protocol.*", attr.name)
    attr.value.ir_type == "String"
    lower(attr.value.value) == insecure_cleartext_protocols[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure unencrypted protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    regex.match("(?i).*protocol.*", entry.key.value)
    entry.value.ir_type == "String"
    lower(entry.value.value) == insecure_cleartext_protocols[_]
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure unencrypted protocol configured in nested configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == insecure_transmission_string_attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == insecure_transmission_string_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Transmission encryption is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(min.*tls|tls.*min|tls.*version|min.*protocol|ssl.*policy)", attr.name)
    attr.value.ir_type == "String"
    lower(attr.value.value) == weak_tls_version_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak or deprecated TLS/SSL version permitted. (CWE-319)"
    }
}