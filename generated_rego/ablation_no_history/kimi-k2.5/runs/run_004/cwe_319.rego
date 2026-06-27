package glitch

import data.glitch_lib

cleartext_schemes := {"http://", "ftp://", "telnet://", "smtp://", "ldap://"}

cleartext_protocols := {"http", "ftp", "telnet", "smtp", "ldap", "tcp", "udp"}

insecure_values := {"false", "no", "off", "disabled", "none", "optional", "0", "http", "ftp", "telnet", "smtp", "ldap"}

is_cleartext_scheme(str) {
    scheme := cleartext_schemes[_]
    startswith(lower(str), lower(scheme))
}

is_cleartext_protocol(str) {
    protocol := cleartext_protocols[_]
    lower(str) == protocol
}

is_insecure_value(val) {
    inv := insecure_values[_]
    lower(val) == inv
}

is_url_like_attr(name) {
    contains(lower(name), "url")
} else {
    contains(lower(name), "endpoint")
} else {
    contains(lower(name), "address")
} else {
    contains(lower(name), "source")
} else {
    contains(lower(name), "host")
} else {
    contains(lower(name), "server")
} else {
    contains(lower(name), "location")
} else {
    contains(lower(name), "path")
} else {
    contains(lower(name), "webhook")
} else {
    contains(lower(name), "callback")
}

is_protocol_attr(name) {
    lower(name) == "protocol"
} else {
    lower(name) == "scheme"
} else {
    endswith(lower(name), "_protocol")
}

is_tls_flag(name) {
    contains(lower(name), "tls")
} else {
    contains(lower(name), "ssl")
} else {
    contains(lower(name), "verify")
} else {
    contains(lower(name), "insecure")
} else {
    contains(lower(name), "encrypt")
} else {
    contains(lower(name), "cert")
} else {
    contains(lower(name), "https")
} else {
    contains(lower(name), "secure")
}

match_boolean_false(node) {
    node.ir_type == "Boolean"
    node.value == false
}

match_insecure_string(node) {
    node.ir_type == "String"
    is_insecure_value(node.value)
}

match_insecure_or_cleartext_string(node) {
    node.ir_type == "String"
    is_insecure_value(node.value)
} else {
    node.ir_type == "String"
    is_cleartext_protocol(node.value)
} else {
    node.ir_type == "String"
    is_cleartext_scheme(node.value)
}

has_insecure_value(node) {
    walk(node, [_, n])
    match_boolean_false(n)
} else {
    walk(node, [_, n])
    match_insecure_string(n)
}

has_cleartext_scheme(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    is_cleartext_scheme(n.value)
}

has_cleartext_protocol(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    is_cleartext_protocol(n.value)
}

hash_has_protocol_with_cleartext(hash) {
    hash.ir_type == "Hash"
    some idx
    entry := hash.value[idx]
    key_node := entry.key
    val_node := entry.value
    key_node.ir_type == "String"
    is_protocol_attr(key_node.value)
    walk(val_node, [_, n])
    n.ir_type == "String"
    is_cleartext_protocol(n.value)
}

hash_has_tls_disabled(hash) {
    hash.ir_type == "Hash"
    some idx
    entry := hash.value[idx]
    key_node := entry.key
    val_node := entry.value
    key_node.ir_type == "String"
    is_tls_flag(key_node.value)
    walk(val_node, [_, n])
    match_boolean_false(n)
} else {
    hash.ir_type == "Hash"
    some idx
    entry := hash.value[idx]
    key_node := entry.key
    val_node := entry.value
    key_node.ir_type == "String"
    is_tls_flag(key_node.value)
    walk(val_node, [_, n])
    match_insecure_string(n)
}

hash_has_insecure_config(hash) {
    hash.ir_type == "Hash"
    some idx
    entry := hash.value[idx]
    key_node := entry.key
    val_node := entry.value
    key_node.ir_type == "String"
    is_protocol_attr(key_node.value)
    walk(val_node, [_, n])
    match_insecure_or_cleartext_string(n)
} else {
    hash.ir_type == "Hash"
    some idx
    entry := hash.value[idx]
    key_node := entry.key
    val_node := entry.value
    key_node.ir_type == "String"
    is_tls_flag(key_node.value)
    walk(val_node, [_, n])
    match_insecure_or_cleartext_string(n)
}

has_cleartext_in_tree(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    is_cleartext_scheme(n.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)

    v := vars[_]

    v.value.ir_type == "Hash"
    hash_has_protocol_with_cleartext(v.value)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable hash with insecure protocol configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    v.value.ir_type == "Hash"
    hash_has_tls_disabled(v.value)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable hash with TLS/SSL disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    v.value.ir_type == "Hash"
    hash_has_insecure_config(v.value)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable hash with insecure encryption configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    is_url_like_attr(v.name)
    v.value.ir_type == "String"
    is_cleartext_scheme(v.value.value)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable with unencrypted URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    is_url_like_attr(v.name)
    has_cleartext_in_tree(v.value)

    result := {
        "type": "sec_https",
        "element": v,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Variable with interpolated unencrypted URL. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_url_like_attr(attr.name)
    has_cleartext_scheme(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted URL detected in sensitive attribute. (CWE-319)"
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
    has_cleartext_protocol(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol configured. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_tls_flag(attr.name)
    has_insecure_value(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - TLS/SSL verification disabled. (CWE-319)"
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
    hash_has_protocol_with_cleartext(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Attribute hash with insecure protocol configuration. (CWE-319)"
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
    hash_has_tls_disabled(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Attribute hash with TLS/SSL disabled. (CWE-319)"
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
    hash_has_insecure_config(attr.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Attribute hash with insecure encryption configuration. (CWE-319)"
    }
}