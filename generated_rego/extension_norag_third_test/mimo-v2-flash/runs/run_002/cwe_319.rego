package glitch

import data.glitch_lib

encryption_keywords := {"validate_certs", "ssl", "tls", "encrypt", "https_only", "secure_transfer", "use_ssl", "ssl_mode", "start_tls"}

unencrypted_protocols := {"http", "ftp", "telnet", "HTTP", "FTP", "TELENET"}

disabled_encryption_values := {"false", "no", "disabled", "off", "disable"}

url_attributes := {"url", "connection_string", "jdbc_url", "dsn"}

check_encryption_disabled(node) {
    node.ir_type == "Boolean"
    node.value == false
} else {
    node.ir_type == "String"
    lower_v := lower(node.value)
    disabled_encryption_values[lower_v]
}

check_unencrypted_protocol(node) {
    node.ir_type == "String"
    lower_v := lower(node.value)
    unencrypted_protocols[lower_v]
} else {
    node.ir_type == "String"
    regex.match("(?i)^(http://|ftp://|telnet://)", node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    encryption_keywords[var.name]
    walk(var.value, [path, node])
    check_encryption_disabled(node)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Encryption disabled in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    encryption_keywords[attr.name]
    walk(attr.value, [path, node])
    check_encryption_disabled(node)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "protocol"
    walk(attr.value, [path, node])
    check_unencrypted_protocol(node)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted protocol used for transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match(".*protocol.*", attr.name)
    walk(attr.value, [path, node])
    check_unencrypted_protocol(node)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted protocol used in configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    url_attributes[attr.name]
    walk(attr.value, [path, node])
    node.ir_type == "String"
    (regex.match("(?i)^http://", node.value) or regex.match("(?i)ssl=false", node.value))
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Unencrypted URL or connection string. (CWE-319)"
    }
}