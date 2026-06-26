package glitch

import data.glitch_lib

integrity_check_attrs := {"verify_checksum", "gpg_check", "gpgcheck", "gpg_verify", "signature_verification", "validate_certs", "tls_verify", "ssl_verify"}

integrity_bypass_attrs := {"skip_checksum", "disable_gpg_check", "no_verify", "allow_unauthenticated", "insecure"}

download_resource_types := {"remote_file", "archive", "get_url", "uri", "wget_fetch", "curl_download", "staging::file"}

source_attr_names := {"url", "source", "src", "script_url", "download_url"}

checksum_attr_names := {"checksum", "sha256", "sha512", "md5", "hash", "integrity", "verify", "verify_checksum"}

is_false_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_false_value(value) {
    value.ir_type == "String"
    regex.match("(?i)^(false|no|disabled)$", value.value)
}

is_false_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_true_value(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_true_value(value) {
    value.ir_type == "String"
    regex.match("(?i)^(true|yes)$", value.value)
}

has_checksum_attr(attrs) {
    attr := attrs[_]
    attr.name == checksum_attr_names[_]
}

has_source_attr(attrs) {
    attr := attrs[_]
    attr.name == source_attr_names[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == integrity_check_attrs[_]
    is_false_value(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification attribute is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == integrity_bypass_attrs[_]
    is_true_value(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity check bypass is explicitly enabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == download_resource_types[_]
    attrs := glitch_lib.all_attributes(node)
    has_source_attr(attrs)
    not has_checksum_attr(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Download resource lacks integrity verification attribute. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == source_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^http://.*", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Resource is fetched over insecure HTTP. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, entry])
    entry.key.ir_type == "String"
    entry.key.value == integrity_check_attrs[_]
    is_false_value(entry.value)

    result := {
        "type": "sec_no_int_check",
        "element": entry.value,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification is disabled in nested configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, entry])
    entry.key.ir_type == "String"
    entry.key.value == integrity_bypass_attrs[_]
    is_true_value(entry.value)

    result := {
        "type": "sec_no_int_check",
        "element": entry.value,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity bypass is enabled in nested configuration. (CWE-353)"
    }
}