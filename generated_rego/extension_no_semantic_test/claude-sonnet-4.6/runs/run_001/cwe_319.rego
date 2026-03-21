package glitch

import data.glitch_lib

protocol_attr_names := {"protocol", "scheme", "listener_protocol", "backend_protocol", "frontend_protocol", "forwarding_protocol"}

insecure_protocols := {"HTTP", "FTP", "TELNET", "SMTP", "LDAP", "http", "ftp", "telnet", "ldap", "smtp"}

https_enforce_attrs := {"https_only", "enable_https", "https_traffic_only", "enforce_https", "require_https", "secure_transfer_required", "secure_transfer", "enableHttpsTrafficOnly", "tls_enabled", "ssl_enabled", "ssl_enforce", "enable_ssl", "encrypt", "encrypted", "encryption_in_transit", "transit_encryption"}

insecure_allow_attrs := {"allow_insecure_connections", "allow_http", "http_allowed", "enable_non_ssl_port"}

tls_version_attrs := {"minimum_tls_version", "tls_version", "ssl_version", "ssl_policy", "tls_policy", "security_policy"}

weak_tls_versions := {"TLS1_0", "TLS1_1", "SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "Policy-Min-TLS-1-0-2019-07"}

skip_verify_attrs := {"skip_tls_verify", "tls_skip_verify", "insecure_skip_verify", "insecure_ssl", "disable_ssl_verification", "no_verify"}

viewer_protocol_attrs := {"viewer_protocol_policy", "origin_protocol_policy"}

insecure_viewer_values := {"allow-all", "http-only"}

db_ssl_attrs := {"sslmode", "ssl_mode", "require_ssl", "ssl"}

insecure_db_ssl := {"disable", "prefer", "none"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == protocol_attr_names[_]
    attr.value.ir_type == "String"
    attr.value.value == insecure_protocols[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol usage - Cleartext protocol (HTTP/FTP/TELNET/LDAP) enables cleartext transmission of sensitive information. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("^(http|ftp|ldap|telnet)://", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure URL scheme - Endpoint URL uses a cleartext transport scheme (http://, ftp://, ldap://). (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == https_enforce_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "HTTPS/TLS enforcement disabled - Secure transport must be enforced to prevent cleartext transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == https_enforce_attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == "disabled"
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "HTTPS/TLS enforcement disabled - Secure transport must be enforced to prevent cleartext transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == insecure_allow_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure connections explicitly allowed - Enabling cleartext or non-SSL connections exposes sensitive data in transit. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == tls_version_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == weak_tls_versions[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Weak or deprecated TLS/SSL version configured - Use TLS 1.2 or higher to prevent weak encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == skip_verify_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "TLS/SSL certificate verification bypassed - Skipping certificate validation enables man-in-the-middle attacks. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == viewer_protocol_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == insecure_viewer_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure viewer/origin protocol policy - Configure HTTPS-only or redirect-to-HTTPS to prevent cleartext transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == db_ssl_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == insecure_db_ssl[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Database connection SSL mode is insecure - Use 'require' or stronger SSL mode to encrypt data in transit. (CWE-319)"
    }
}