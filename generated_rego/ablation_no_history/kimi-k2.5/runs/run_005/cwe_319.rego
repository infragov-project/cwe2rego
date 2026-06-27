package glitch

import data.glitch_lib

unencrypted_protocol_prefixes := ["^http://", "^ftp://", "^telnet://", "^ldap://", "^smtp://"]

weak_tls_versions := ["tlsv1.0", "tlsv1.1", "sslv2", "sslv3", "1.0", "1.1", "ssl3", "ssl2"]

disable_values := ["false", "off", "disabled", "no"]

encryption_attr_keywords := ["ssl", "tls", "https", "secure", "encrypt"]

validate_attr_names := ["validate_certs", "ssl_verify", "verify_ssl", "verify_peer", "verify"]

protocol_attr_names := ["protocol", "url", "source", "endpoint", "address", "host", "uri", "base_url", "api_url"]

has_string_starting_with_unencrypted_protocol(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    val := lower(n.value)
    some prefix
    regex.match(unencrypted_protocol_prefixes[prefix], val)
}

is_disabled_value(node) {
    node.ir_type == "Boolean"
    node.value == false
} else {
    node.ir_type == "String"
    lower(node.value) == disable_values[_]
} else {
    node.ir_type == "Integer"
    node.value == 0
}

is_weak_tls_version(node) {
    node.ir_type == "String"
    val := lower(node.value)
    val == weak_tls_versions[_]
}

attr_name_indicates_protocol(attr_name) {
    lower(attr_name) == protocol_attr_names[_]
}

attr_name_indicates_validation(attr_name) {
    lower(attr_name) == validate_attr_names[_]
}

attr_name_indicates_encryption(attr_name) {
    attr_lower := lower(attr_name)
    some kw
    contains(attr_lower, encryption_attr_keywords[kw])
}

contains_unencrypted_protocol_in_string_union(node) {
    node.ir_type == "String"
    val := lower(node.value)
    some prefix
    regex.match(unencrypted_protocol_prefixes[prefix], val)
} else {
    node.ir_type == "Sum"
    contains_unencrypted_protocol_in_string_union(node.left)
} else {
    node.ir_type == "Sum"
    contains_unencrypted_protocol_in_string_union(node.right)
}

hash_has_protocol_key_with_unencrypted_value(hash) {
    hash.ir_type == "Hash"
    some k
    entry := hash.value[k]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "protocol"
    entry.value.ir_type == "String"
    lower(entry.value.value) == "http"
}

hash_has_disabled_encryption(hash, attr_name) {
    hash.ir_type == "Hash"
    attr_name_indicates_encryption(attr_name)
    some k
    entry := hash.value[k]
    entry.key.ir_type == "String"
    key_lower := lower(entry.key.value)
    some kw
    contains(key_lower, encryption_attr_keywords[kw])
    is_disabled_value(entry.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    attr_name_indicates_protocol(attr.name)
    contains_unencrypted_protocol_in_string_union(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol (http://, ftp://, etc.) used in URL or endpoint configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    attr_name_indicates_validation(attr.name)
    is_disabled_value(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL/TLS certificate validation disabled. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    hash_has_protocol_key_with_unencrypted_value(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTP protocol configured instead of HTTPS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    hash_has_disabled_encryption(attr.value, attr.name)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption explicitly disabled in configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "Hash"
    hash_has_protocol_key_with_unencrypted_value(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - HTTP protocol configured instead of HTTPS. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    attr_name_indicates_protocol(var.name)
    contains_unencrypted_protocol_in_string_union(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted protocol (http://, ftp://, etc.) used in URL or endpoint configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    is_weak_tls_version(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Weak or deprecated TLS/SSL version configured. (CWE-319)"
    }
}