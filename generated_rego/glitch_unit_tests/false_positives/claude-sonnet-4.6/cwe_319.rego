package glitch

import data.glitch_lib

cleartext_url_pattern := "(?i)^(http://|ftp://|ldap://|amqp://|redis://|ws://)"

secure_enforcement_fields := {
    "https_only", "enable_https_traffic_only",
    "require_ssl", "enforce_https", "secure_transfer_required",
    "require_secure_transport", "ssl_enabled", "tls_enabled",
    "transit_encryption_enabled", "tls_required", "require_tls",
    "in_transit_encryption", "encryption_in_transit",
    "cookie_secure", "session_cookie_secure"
}

cleartext_protocols := {"http", "ftp", "telnet", "smtp", "ldap"}

protocol_attr_names := {
    "protocol", "listener_protocol", "backend_protocol",
    "forwarding_protocol", "scheme"
}

value_has_cleartext_url(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    regex.match(cleartext_url_pattern, node.value)
}

is_false_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_false_value(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_false_value(value) {
    value.ir_type == "Integer"
    value.value == 0
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
        "description": "Cleartext transmission of sensitive information - Attribute value uses an unencrypted protocol URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    value_has_cleartext_url(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable value uses an unencrypted protocol URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == secure_enforcement_fields[_]
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Secure transfer enforcement is explicitly disabled. (CWE-319)"
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
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol explicitly configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "connection_string"
    attr.value.ir_type == "String"
    regex.match("(?i)(sslmode=disable|encrypt=false|ssl=false|usessl=false)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Connection string disables SSL/TLS encryption. (CWE-319)"
    }
}