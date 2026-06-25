package glitch

import data.glitch_lib

cleartext_url_prefixes := {"http://", "ftp://", "telnet://", "smtp://", "ldap://"}
cleartext_protocols := {"http", "ftp", "telnet", "smtp", "ldap", "tcp", "udp", "plaintext"}
weak_tls_versions := {"1.0", "1.1", "tls1.0", "tls1.1"}
disabled_values := {"false", "disabled", "disable", "off", "none", "optional", "allow", "prefer", "no"}

all_expr_strings(expr) = strings {
    strings := {str |
        walk(expr, [_, node])
        node.ir_type == "String"
        str := lower(node.value)
    }
}

all_expr_booleans(expr) = bools {
    bools := {b |
        walk(expr, [_, node])
        node.ir_type == "Boolean"
        b := node.value
    }
}

all_expr_integers(expr) = ints {
    ints := {i |
        walk(expr, [_, node])
        node.ir_type == "Integer"
        i := node.value
    }
}

all_expr_floats(expr) = floats {
    floats := {f |
        walk(expr, [_, node])
        node.ir_type == "Float"
        f := node.value
    }
}

has_cleartext_url_in_expr(expr) {
    str := all_expr_strings(expr)[_]
    prefix := cleartext_url_prefixes[_]
    startswith(str, prefix)
}

has_cleartext_protocol_in_expr(expr) {
    str := all_expr_strings(expr)[_]
    str == cleartext_protocols[_]
}

has_disabled_encryption_in_expr(expr) {
    b := all_expr_booleans(expr)[_]
    b == false
}

has_disabled_encryption_in_expr(expr) {
    str := all_expr_strings(expr)[_]
    str == disabled_values[_]
}

has_disabled_encryption_in_expr(expr) {
    i := all_expr_integers(expr)[_]
    i == 0
}

has_weak_tls_in_expr(expr) {
    str := all_expr_strings(expr)[_]
    str == weak_tls_versions[_]
}

has_weak_tls_in_expr(expr) {
    f := all_expr_floats(expr)[_]
    f == 1.0
}

has_weak_tls_in_expr(expr) {
    f := all_expr_floats(expr)[_]
    f == 1.1
}

is_cert_validation_attr(name) {
    lower_name := lower(name)
    regex.match(".*(validate_cert|verify_cert|verify_ssl|ssl_verify|verify|insecure|cert).*", lower_name)
}

is_encryption_control_attr(name) {
    lower_name := lower(name)
    regex.match(".*(encryption|ssl|tls|min.*tls|minimum.*tls|secure|transport).*", lower_name)
}

is_protocol_attr(name) {
    lower_name := lower(name)
    regex.match("^(protocol|scheme|url|source|endpoint|address|uri|target|destination|host|location|base_url|root_url|serve_from|api_endpoint|web_uri|redirect_uri)$", lower_name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_cert_validation_attr(attr.name)
    has_disabled_encryption_in_expr(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Certificate validation is disabled, allowing unencrypted or unverified connections. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_encryption_control_attr(attr.name)
    has_disabled_encryption_in_expr(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption for data transmission is disabled, allowing sensitive data to travel unencrypted. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_encryption_control_attr(attr.name)
    has_weak_tls_in_expr(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak or deprecated TLS version configured, providing insufficient encryption strength. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_protocol_attr(attr.name)
    has_cleartext_protocol_in_expr(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext protocol configured for data transmission without encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    has_cleartext_url_in_expr(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - URL configured with unencrypted HTTP or other cleartext protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    
    is_protocol_attr(node.name)
    has_cleartext_protocol_in_expr(node.value)
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext protocol configured for data transmission without encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    
    has_cleartext_url_in_expr(node.value)
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - URL configured with unencrypted HTTP or other cleartext protocol. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    key_str := entry.key.value
    is_protocol_attr(key_str)
    has_cleartext_protocol_in_expr(entry.value)
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Cleartext protocol configured for data transmission without encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    key_str := entry.key.value
    is_encryption_control_attr(key_str)
    has_disabled_encryption_in_expr(entry.value)
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption for data transmission is disabled, allowing sensitive data to travel unencrypted. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    key_str := entry.key.value
    is_encryption_control_attr(key_str)
    has_weak_tls_in_expr(entry.value)
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak or deprecated TLS version configured, providing insufficient encryption strength. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    has_cleartext_url_in_expr(entry.value)
    
    result := {
        "type": "sec_https",
        "element": entry,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - URL configured with unencrypted HTTP or other cleartext protocol. (CWE-319)"
    }
}