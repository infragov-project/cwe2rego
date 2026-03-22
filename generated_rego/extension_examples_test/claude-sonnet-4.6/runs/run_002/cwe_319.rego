package glitch

import data.glitch_lib

value_has_cleartext_url(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap|smtp)://", n.value)
}

is_disabled_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled_value(value) {
    value.ir_type == "String"
    lower(value.value) == {"no", "false", "0", "disabled"}[_]
}

is_enabled_value(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_enabled_value(value) {
    value.ir_type == "String"
    lower(value.value) == {"yes", "true", "1"}[_]
}

security_enforce_names := {
    "enable_https_traffic_only", "https_only", "secure_transfer_required",
    "require_ssl", "ssl_enforcement_enabled", "enforce_https",
    "in_transit_encryption_enabled", "encrypt_in_transit",
    "transit_encryption_enabled", "node_to_node_encryption_enabled",
    "in_cluster_encryption", "redirect_http_to_https", "validate_certs"
}

insecurity_names := {"insecure", "disable_ssl", "skip_tls_verify"}

cleartext_protocols := {
    "http", "ftp", "telnet", "ldap", "smtp", "amqp", "ws", "plaintext", "tls_plaintext"
}

protocol_attr_names := {"protocol", "listener_protocol", "transport_type", "scheme"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == security_enforce_names[_]
    is_disabled_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption enforcement disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == insecurity_names[_]
    is_enabled_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure transport explicitly enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == protocol_attr_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == cleartext_protocols[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol specified. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    value_has_cleartext_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext URL in attribute value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    value_has_cleartext_url(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext URL in variable. (CWE-319)"
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
    lower(entry.key.value) == protocol_attr_names[_]
    entry.value.ir_type == "String"
    lower(entry.value.value) == cleartext_protocols[_]
    result := {
        "type": "sec_https",
        "element": entry.key,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in variable definition. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"minimum_tls_version", "min_tls_version", "min_protocol_version"}[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(tls1[\\._ ]?0|tls1[\\._ ]?1|sslv3|tlsv1$)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak TLS version configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"viewer_protocol_policy", "origin_protocol_policy"}[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"allow-all", "http-only"}[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Protocol policy allows unencrypted traffic. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "ssl_mode"
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"disable", "allow"}[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL mode allows cleartext connections. (CWE-319)"
    }
}