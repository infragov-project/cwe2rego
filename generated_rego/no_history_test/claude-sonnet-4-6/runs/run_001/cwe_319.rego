package glitch

import data.glitch_lib

ssl_tls_false_attrs := {
    "ssl_enabled", "tls_enabled", "enable_ssl", "require_ssl",
    "ssl_enforcement_enabled", "enforce_ssl", "use_ssl", "tls",
    "transit_encryption_enabled", "in_transit_encryption",
    "encryption_in_transit", "enable_https_traffic_only",
    "https_only", "enforce_https", "https_traffic_only",
    "require_https", "http_redirect", "redirect_http_to_https",
    "force_ssl", "validate_certs"
}

ssl_tls_true_attrs := {"insecure", "disable_tls"}

weak_tls_versions := {
    "TLS1_0", "TLS1_1", "1.0", "1.1",
    "SSLv3", "TLSv1", "TLSv1_1", "ELBSecurityPolicy-2016-08"
}

min_tls_attrs := {"min_tls_version", "minimum_tls_version", "tls_version"}

insecure_protocol_attrs := {"protocol", "scheme", "listener_protocol", "backend_protocol"}

is_false_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_false_value(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_false_value(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

has_http_url(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    startswith(lower(n.value), "http://")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ssl_tls_false_attrs[_]
    is_false_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS or HTTPS is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ssl_tls_true_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure flag is enabled or TLS is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "ssl_enforcement"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "disabled"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL enforcement is explicitly disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == insecure_protocol_attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == "http"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure HTTP protocol is configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    has_http_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Endpoint uses insecure HTTP scheme. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    has_http_url(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Variable uses insecure HTTP scheme. (CWE-319)"
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
    entry.key.value == insecure_protocol_attrs[_]
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure HTTP protocol in hash configuration. (CWE-319)"
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
    entry.key.value == ssl_tls_false_attrs[_]
    is_false_value(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS disabled in hash configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == insecure_protocol_attrs[_]
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure HTTP protocol in hash configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == ssl_tls_false_attrs[_]
    is_false_value(entry.value)
    result := {
        "type": "sec_https",
        "element": entry.value,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL/TLS disabled in hash configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == min_tls_attrs[_]
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
    attr.name == "require_secure_transport"
    attr.value.ir_type == "String"
    upper(attr.value.value) == "OFF"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Secure transport is not required for database connections. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "ssl_mode"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "disable"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - SSL mode is disabled for database connection. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "transport_security"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "none"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Transport security is set to none. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "connection_string"
    attr.value.ir_type == "String"
    regex.match("(?i)(Encrypt=False|TrustServerCertificate=True)", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Connection string disables encryption or certificate validation. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "protocols"
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    lower(elem.value) == "http"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP is included in the allowed protocols list. (CWE-319)"
    }
}