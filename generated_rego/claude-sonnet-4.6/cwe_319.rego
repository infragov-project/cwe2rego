package glitch

import data.glitch_lib

https_tls_enforcement_names := {
    "https_only", "enable_https", "https_traffic_only", "enforce_https",
    "secure_transfer_enabled", "require_secure_transfer",
    "ssl_enabled", "tls_enabled", "tls_required"
}

encryption_enforcement_names := {
    "encryption_in_transit", "ssl_enforcement", "require_ssl", "force_ssl",
    "enable_https_traffic_only", "secure_transfer",
    "transit_encryption", "in_transit_encryption", "transit_encryption_enabled"
}

internal_encryption_names := {
    "node_to_node_encryption", "peer_tls_enabled", "intra_cluster_tls",
    "internal_tls", "mutual_tls", "encrypt_inter_node_communications"
}

redirect_attr_names := {"redirect_http_to_https", "http_to_https_redirect"}

cookie_secure_names := {"secure", "cookie_secure", "session_secure"}

weak_tls_versions := {
    "tls1_0", "tls1_1", "sslv3", "sslv2", "tlsv1.0", "tlsv1.1"
}

insecure_protocol_values := {
    "http", "ftp", "telnet", "smtp", "pop3", "imap", "ldap", "ws"
}

insecure_ports := {80, 21, 23, 110, 143, 389, 1080}

insecure_viewer_origin_policies := {"allow-all", "http-only"}

is_false_or_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_false_or_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "disabled"
}

is_false_or_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_false_or_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "none"
}

expr_contains_http_url(expr) {
    walk(expr, [_, node])
    node.ir_type == "String"
    startswith(lower(node.value), "http://")
}

url_related_name(name) {
    regex.match(`(?i).*(url|uri|endpoint|connection|backend|origin|href|link|address).*`, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == https_tls_enforcement_names[_]
    is_false_or_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTPS/TLS/SSL enforcement is disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == encryption_enforcement_names[_]
    is_false_or_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption in transit is disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == internal_encryption_names[_]
    is_false_or_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Node-to-node or intra-cluster encryption is disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == redirect_attr_names[_]
    is_false_or_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP to HTTPS redirection is disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cookie_secure_names[_]
    is_false_or_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Cookie or session secure flag is disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"minimum_tls_version", "min_tls_version", "ssl_policy", "tls_policy", "tls_version"}[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == weak_tls_versions[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Weak or deprecated TLS/SSL version is configured (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"protocol", "listener_protocol", "frontend_protocol", "backend_protocol"}[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == insecure_protocol_values[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure unencrypted protocol is configured (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "scheme"
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"http", "ftp", "telnet"}[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure cleartext URL scheme is used (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"port", "listener_port", "backend_port", "target_port"}[_]
    attr.value.ir_type == "Integer"
    attr.value.value == insecure_ports[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure cleartext service port is configured (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"viewer_protocol_policy", "origin_protocol_policy"}[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == insecure_viewer_origin_policies[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - CDN or distribution protocol policy allows unencrypted HTTP traffic (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    url_related_name(attr.name)
    expr_contains_http_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP (unencrypted) URL used in endpoint or connection attribute (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    url_related_name(v.name)
    expr_contains_http_url(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - HTTP (unencrypted) URL used in variable configuration (CWE-319)"
    }
}