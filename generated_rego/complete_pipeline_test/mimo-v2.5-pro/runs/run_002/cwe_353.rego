package glitch

import data.glitch_lib

_integrity_disable_fields := {
    "validate_certs", "verify_ssl", "ssl_verify", "verify",
    "gpgcheck", "repo_gpgcheck", "sslverify",
    "checksum", "integrity_check", "digest",
    "verify_checksum", "verify_integrity",
    "enable_checksum", "checksum_enabled", "validation"
}

_encryption_disable_fields := {
    "ssl", "tls", "use_ssl", "enable_tls",
    "ssl_enforce", "enforce_ssl"
}

_security_disable_fields := _integrity_disable_fields | _encryption_disable_fields

_integrity_presence_fields := _integrity_disable_fields | {
    "hash", "sha256", "sha512", "md5",
    "signature", "signed", "checksum_type"
}

_download_resource_types := {
    "remote_file", "get_url", "wget", "curl",
    "fetch", "download", "uri", "package",
    "archive", "yum", "apt", "pip", "gem",
    "npm", "docker_image"
}

_disabled_string_values := {"no", "false", "0", "disabled", "none", "off", "n"}

is_disabled_value(v) {
    v.ir_type == "String"
    lower(v.value) == _disabled_string_values[_]
}

is_disabled_value(v) {
    v.ir_type == "Boolean"
    v.value == false
}

is_disabled_value(v) {
    v.ir_type == "Integer"
    v.value == 0
}

is_disabled_value(v) {
    v.ir_type == "Null"
}

is_disabled_value(v) {
    v.ir_type == "Undef"
}

is_disabled_value(v) {
    v.ir_type == "String"
    trim_space(v.value) == ""
}

has_integrity_presence(attrs) {
    attr := attrs[_]
    attr.name == _integrity_presence_fields[_]
}

find_disabled_hash_entries(node) = entries {
    entries := {e |
        walk(node, [_, e])
        is_object(e)
        e.key
        e.value
        e.key.ir_type == "String"
        e.key.value == _integrity_disable_fields[_]
        is_disabled_value(e.value)
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == _security_disable_fields[_]
    is_disabled_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check - Security verification is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == _download_resource_types[_]
    attrs := glitch_lib.all_attributes(node)
    not has_integrity_presence(attrs)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check - Download resource without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    entries := find_disabled_hash_entries(var.value)
    entry := entries[_]
    result := {
        "type": "sec_no_int_check",
        "element": entry.key,
        "path": parent.path,
        "description": "Missing integrity check - Integrity verification disabled in configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.name == _security_disable_fields[_]
    is_disabled_value(var.value)
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "Missing integrity check - Security check disabled in variable. (CWE-353)"
    }
}