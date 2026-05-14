package glitch

import data.glitch_lib

is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled(value) {
    value.ir_type == "String"
    regex.match("(?i)^(false|disabled|off|0|no)$", value.value)
}

is_disabled(value) {
    value.ir_type == "Integer"
    value.value == 0
}

has_insecure_url(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap|smtp|ws)://", n.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    has_insecure_url(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in attribute value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    has_insecure_url(v.value)
    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in variable value. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    kv.key.ir_type == "String"
    kv.key.value == "protocol"
    kv.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet|ldap|smtp|ws)$", kv.value.value)
    result := {
        "type": "sec_https",
        "element": kv.value,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol configured in Hash. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(ssl_enabled|tls_enabled|enable_ssl|require_ssl|ssl_enforcement|enable_https_traffic_only|https_only|force_https|require_https|secure_transfer_required|require_secure_transport|in_transit_encryption|encrypt_in_transit|transit_encryption_enabled|in_transit_encryption_enabled|validate_certs|redirect_http_to_https|http_to_https_redirect|http_redirect|secure|secure_flag|cookie_secure)$", attr.name)
    is_disabled(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption or security enforcement is disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(ssl_mode|sslmode)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^disable(d)?$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL mode disabled for database. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(minimum_tls_version|min_tls_version|tls_policy|ssl_policy|security_policy)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(TLSv?1[._]?[01]|TLS_1_[01]|SSLv[23])", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak or deprecated TLS/SSL version permitted. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(viewer_protocol_policy|origin_protocol_policy)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(allow-all|http-only)$", attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Protocol policy allows unencrypted HTTP traffic. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^port$", attr.name)
    attr.value.ir_type == "Integer"
    insecure_ports := {80, 21, 23, 25, 389, 1080}
    attr.value.value == insecure_ports[_]
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure plaintext protocol port configured. (CWE-319)"
    }
}