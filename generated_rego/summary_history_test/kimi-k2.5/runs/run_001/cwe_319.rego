package glitch

import data.glitch_lib

insecure_protocols := {"http", "ftp", "telnet", "smtp", "http://", "ftp://", "telnet://", "smtp://"}

encryption_tls_attrs := {"encryption", "tls", "ssl", "encrypted", "in_transit_encryption", "encryption_in_transit", "https_only", "secure_transport", "enforce_tls", "require_ssl", "minimum_tls_version", "min_tls_version", "ssl_policy", "tls_policy", "tls_mode", "ssl_mode", "validate_certs", "verify_ssl", "ssl_verify", "tls_verify"}

insecure_encryption_values := {"disabled", "false", "none", "optional", "disable", "off", "no", "0", ""}

insecure_tls_versions := {"1.0", "1.1", "tls_1_0", "tls_1_1", "sslv3", "sslv2", "ssl3", "ssl2"}

unencrypted_ports := {80, 21, 23, 25, 110, 143, 587, 8080}

port_attrs := {"port", "from_port", "to_port", "container_port", "host_port"}

is_insecure_protocol_str(val) {
    lowered := lower(val)
    insecure_protocols[lowered]
} else {
    lowered := lower(val)
    startswith(lowered, "http://")
} else {
    lowered := lower(val)
    startswith(lowered, "ftp://")
} else {
    lowered := lower(val)
    startswith(lowered, "telnet://")
} else {
    lowered := lower(val)
    startswith(lowered, "smtp://")
}

check_insecure_tls_value(value) {
    value.ir_type == "String"
    lowered := lower(value.value)
    insecure_encryption_values[lowered]
} else {
    value.ir_type == "String"
    lowered := lower(value.value)
    insecure_tls_versions[lowered]
} else {
    value.ir_type == "Boolean"
    value.value == false
}

is_insecure_tls_config(attr) {
    encryption_tls_attrs[lower(attr.name)]
    check_insecure_tls_value(attr.value)
}

is_insecure_port_value(value) {
    value.ir_type == "Integer"
    unencrypted_ports[value.value]
} else {
    value.ir_type == "String"
    port_num := to_number(value.value)
    unencrypted_ports[port_num]
}

has_insecure_connection_string(value) {
    value.ir_type == "String"
    conn := lower(value.value)
    contains(conn, "encrypt=false")
} else {
    value.ir_type == "String"
    conn := lower(value.value)
    contains(conn, "sslmode=disable")
} else {
    value.ir_type == "String"
    conn := lower(value.value)
    contains(conn, "tls=false")
} else {
    value.ir_type == "String"
    conn := lower(value.value)
    contains(conn, "ssl=false")
}

walk_for_insecure_protocol(val) {
    walk(val, [_, n])
    n.ir_type == "String"
    is_insecure_protocol_str(n.value)
}

hash_has_protocol_key_insecure(hash) {
    some entry
    entry = hash.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    is_insecure_protocol_str(entry.value.value)
}

hash_is_insecure(hash) {
    walk_for_insecure_protocol(hash)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_insecure_tls_config(attr)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption/TLS for data transmission is disabled or set to insecure values. (CWE-319)"
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
    is_insecure_protocol_str(attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in attribute value transmits data without encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    walk_for_insecure_protocol(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in attribute value transmits data without encryption. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    hash_has_protocol_key_insecure(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash attribute contains insecure protocol configuration for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    hash_is_insecure(attr.value)
    not hash_has_protocol_key_insecure(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash attribute contains insecure URL for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    port_attrs[lower(attr.name)]
    is_insecure_port_value(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted port configured for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    hash_has_protocol_key_insecure(var.value)

    result := {
        "type": "sec_https",
        "element": {"ir_type": "Attribute", "line": var.value.line, "code": var.code, "name": "protocol", "value": var.value},
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash variable contains insecure protocol configuration for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    hash_is_insecure(var.value)
    not hash_has_protocol_key_insecure(var.value)

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Hash variable contains insecure URL for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    is_insecure_protocol_str(var.value.value)

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable uses insecure protocol for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    walk_for_insecure_protocol(var.value)

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable with composite value uses insecure protocol for data transmission. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    has_insecure_connection_string(var.value)

    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Connection string disables encryption for data transmission. (CWE-319)"
    }
}