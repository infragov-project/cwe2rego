package glitch

import data.glitch_lib

cleartext_protocol_attrs := {"protocol", "scheme", "transport", "listener_protocol", "backend_protocol", "frontend_protocol", "target_protocol"}

https_enforcement_attrs := {"https_only", "enable_https_traffic_only", "enableHttpsTrafficOnly", "require_ssl", "ssl_enabled", "ssl_enforcement_enabled", "secure_transfer_required", "require_https", "force_ssl", "https_traffic_only"}

tls_version_attrs := {"minimum_tls_version", "tls_min_version"}

weak_tls_cipher_attrs := {"ssl_cipher_suite", "ssl_protocol", "ssl_policy", "tls_policy"}

transit_encryption_attrs := {"tls_enabled", "encryption_in_transit", "transit_encryption_enabled"}

ssl_bypass_true_attrs := {"skip_ssl_verification", "insecure_skip_tls_verify", "tls_skip_verify", "insecure"}

ssl_bypass_false_attrs := {"verify_ssl", "ssl_verify", "validate_certs"}

cleartext_url_attrs := {"endpoint", "url", "connection_string"}

cleartext_ports := {80, 21, 23, 25, 110, 143, 389, 1883, 8080, 8000}

port_attr_names := {"port", "ingress_port", "container_port", "target_port", "exposed_port"}

weak_version_pattern := "(?i)(TLSv1\\.0|TLSv1\\.1|SSLv2|SSLv3|TLS1_0|TLS1_1)"

content_cleartext_pattern := "(?i)(listen\\s+80\\b|protocol\\s*[=:]\\s*http\\b|enable_tls\\s*[=:]\\s*false|tls_enabled\\s*[=:]\\s*false|use_ssl\\s*[=:]\\s*false)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    cleartext_protocol_attrs[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|smtp|ldap|mqtt|plaintext|none)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext protocol specified. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "service"
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|smtp|ldap|mqtt|pop3|imap)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext network service enabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    cleartext_url_attrs[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|ldap)://", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext URL or endpoint specified. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    https_enforcement_attrs[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTPS/SSL enforcement disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    https_enforcement_attrs[attr.name]
    attr.value.ir_type == "String"
    upper(attr.value.value) == "DISABLED"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTPS/SSL enforcement set to Disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    tls_version_attrs[attr.name]
    attr.value.ir_type == "String"
    regex.match(weak_version_pattern, attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak or deprecated TLS version configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    weak_tls_cipher_attrs[attr.name]
    attr.value.ir_type == "String"
    regex.match(weak_version_pattern, attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak TLS/SSL cipher or protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    transit_encryption_attrs[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption in transit disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    ssl_bypass_true_attrs[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL/TLS verification bypassed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    ssl_bypass_false_attrs[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL certificate verification disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    port_attr_names[attr.name]
    attr.value.ir_type == "Integer"
    cleartext_ports[attr.value.value]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext protocol port exposed. (CWE-319)"
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
    regex.match(content_cleartext_pattern, attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - File content configures cleartext communication. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "ssl_verify_mode"
    attr.value.ir_type == "VariableReference"
    regex.match("(?i):?none", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL verification mode disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "ssl_verify_mode"
    attr.value.ir_type == "String"
    regex.match("(?i)^(none|disabled)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL verification mode disabled. (CWE-319)"
    }
}