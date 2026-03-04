package glitch

import data.glitch_lib

cleartext_proto_pattern := "(?i)^(http://|ftp://|telnet://|ldap://)"

https_required_flags := {
    "enable_https_traffic_only", "https_only", "secure_transfer_enabled",
    "force_https", "require_ssl", "ssl_enabled", "tls_enabled",
    "enforce_https", "transit_encryption_enabled", "tls_required",
    "redirect_http_to_https"
}

tls_version_attrs := {
    "min_tls_version", "tls_version", "ssl_protocol", "minimum_protocol_version"
}

weak_tls_versions := {
    "tls1.0", "tls1.1", "sslv3", "sslv2", "tlsv1", "tlsv1.0", "tlsv1.1"
}

cert_enforce_flags := {"verify_ssl", "certificate_validation", "ssl_verify"}
cert_skip_flags := {"insecure_ssl", "skip_verify", "tls_skip_verify"}
cookie_flags := {"cookie_secure", "secure_cookie", "session_cookie_secure", "https_only_cookie"}
listener_proto_attrs := {"listener_protocol", "endpoint_type", "target_protocol", "ingress_protocol", "protocol", "scheme"}
cleartext_ports := {80, 21, 23, 389}
port_attrs := {"port", "listener_port", "frontend_port", "backend_port"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    glitch_lib.traverse(attr.value, cleartext_proto_pattern)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - Use of insecure unencrypted protocol in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    glitch_lib.traverse(v.value, cleartext_proto_pattern)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission - Use of insecure unencrypted protocol in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    https_required_flags[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - HTTPS/SSL enforcement is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "http_allowed"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - HTTP traffic is explicitly allowed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    tls_version_attrs[attr.name]
    attr.value.ir_type == "String"
    weak_tls_versions[lower(attr.value.value)]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - Deprecated TLS/SSL version configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    cert_enforce_flags[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - SSL/TLS certificate validation is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    cert_skip_flags[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - SSL/TLS certificate verification is bypassed. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    cookie_flags[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - Session cookie Secure flag is not set. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    listener_proto_attrs[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - Insecure plaintext listener or endpoint protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    port_attrs[attr.name]
    attr.value.ir_type == "Integer"
    cleartext_ports[attr.value.value]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission - Use of cleartext service port. (CWE-319)"
    }
}