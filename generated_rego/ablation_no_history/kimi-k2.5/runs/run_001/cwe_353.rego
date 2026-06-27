package glitch

import data.glitch_lib

integrity_fields := {"gpgcheck", "repo_gpgcheck", "pkg_gpgcheck", "signature_check", "checksum", "sha256_checksum", "md5_checksum", "sha512_checksum", "hash", "digest", "signature", "hmac", "mac", "integrity_check", "verify_integrity", "checksum_verification", "content_hash", "signed_payload"}
ssl_verify_fields := {"validate_certs", "verify_ssl", "ssl_verification", "ssl_verify", "verify_peer", "verify_host", "tls_verify", "cert_validation", "verify"}
insecure_flags := {"insecure", "skip_verify", "skip_validation", "disable_encryption", "allow_unencrypted", "insecure_registry", "skip_tls_verify", "ssl_no_verify"}

protocol_fields := {"protocol", "scheme", "transport"}
plaintext_protocols := {"http", "ftp", "tcp", "udp", "plain", "unencrypted", "raw"}
port_fields := {"port", "listener_port"}
plaintext_ports := {"80", "21", "23", "25"}

disabled_strings := {"false", "no", "disabled", "none", "0", "off"}

is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "Integer"
    value.value == 0
} else {
    value.ir_type == "String"
    lower(value.value) == disabled_strings[_]
} else {
    value.ir_type == "Null"
}

is_enabled(value) {
    value.ir_type == "Boolean"
    value.value == true
} else {
    value.ir_type == "Integer"
    value.value == 1
} else {
    value.ir_type == "String"
    lower(value.value) == {"true", "yes", "enabled", "on", "1"}[_]
}

field_name_matches(name, patterns) {
    lower(name) == lower(patterns[_])
}

has_protocol_attribute(node, attrs) {
    attr := attrs[_]
    field_name_matches(attr.name, protocol_fields)
    attr.value.ir_type == "String"
    lower(attr.value.value) == plaintext_protocols[_]
}

has_port_attribute(node, attrs) {
    attr := attrs[_]
    field_name_matches(attr.name, port_fields)
    attr.value.ir_type == "String"
    attr.value.value == plaintext_ports[_]
} else {
    attr := attrs[_]
    field_name_matches(attr.name, port_fields)
    attr.value.ir_type == "Integer"
    sprintf("%d", [attr.value.value]) == plaintext_ports[_]
}

is_verify_disabled_attr(attr) {
    field_name_matches(attr.name, ssl_verify_fields)
    is_disabled(attr.value)
}

is_integrity_disabled_attr(attr) {
    field_name_matches(attr.name, integrity_fields)
    is_disabled(attr.value)
}

is_insecure_enabled_attr(attr) {
    field_name_matches(attr.name, insecure_flags)
    is_enabled(attr.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := parent.variables[_]
    walk(vars.value, [_, hash_entry])
    hash_entry.ir_type == "Hash"
    some key in hash_entry.value
    field_name_matches(key, {"gpgcheck", "repo_gpgcheck", "pkg_gpgcheck"})
    is_disabled(hash_entry.value[key])
    result := {
        "type": "sec_no_int_check",
        "element": {"name": key, "value": hash_entry.value[key], "line": vars.line},
        "path": parent.path,
        "description": "Missing support for integrity check - GPG check disabled in repository configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := parent.attributes[_]
    field_name_matches(attrs.name, {"skip_verify", "verify_ssl", "ssl_verify"})
    is_disabled(attrs.value)
    result := {
        "type": "sec_no_int_check",
        "element": attrs,
        "path": parent.path,
        "description": "Missing support for integrity check - SSL/TLS verification disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_verify_disabled_attr(attr)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - SSL/TLS verification disabled in atomic unit. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_integrity_disabled_attr(attr)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification mechanism disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_insecure_enabled_attr(attr)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure flag enabled, bypassing security checks. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    has_protocol_attribute(node, attrs)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Plaintext protocol used without integrity protection. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    has_port_attribute(node, attrs)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Unencrypted default port used without security controls. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "url"
    attr.value.ir_type == "String"
    startswith(lower(attr.value.value), "http://")
    not has_integrity_verification(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - HTTP URL without integrity verification. (CWE-353)"
    }
}

has_integrity_verification(node) {
    walk(node, [_, n])
    n.ir_type == "Attribute"
    field_name_matches(n.name, integrity_fields)
    not is_disabled(n.value)
}