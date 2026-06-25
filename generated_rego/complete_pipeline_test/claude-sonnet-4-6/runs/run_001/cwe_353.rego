package glitch

import data.glitch_lib

integrity_disabled_attrs := {
    "gpg_check", "gpgcheck", "repo_gpgcheck", "verify_checksum",
    "ssl_verify", "verify_ssl", "tls_verify", "data_integrity_check"
}

skip_integrity_attrs := {
    "insecure_skip_verify", "tls_insecure_skip_verify", "skip_checksum",
    "disable_gpg_check", "skip_gpg_check", "skip_integrity_check",
    "bypass_integrity"
}

url_attr_names := {"url", "source_url", "download_url", "source"}

integrity_attr_names := {
    "checksum", "sha256", "md5", "sha1", "hash", "digest", "integrity",
    "signature", "content_digest", "image_digest"
}

is_disabled_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled_value(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_disabled_value(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

is_disabled_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_enabled_value(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_enabled_value(value) {
    value.ir_type == "String"
    v := lower(value.value)
    v == "true"
}

is_enabled_value(value) {
    value.ir_type == "String"
    lower(value.value) == "yes"
}

has_integrity_attr(node) {
    attr := node.attributes[_]
    lower(attr.name) == integrity_attr_names[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    lower(attr.name) == integrity_disabled_attrs[_]
    is_disabled_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    lower(attr.name) == skip_integrity_attrs[_]
    is_enabled_value(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity check is explicitly skipped. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == integrity_disabled_attrs[_]
    is_disabled_value(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry.key,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification is disabled in nested configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == skip_integrity_attrs[_]
    is_enabled_value(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry.key,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity check is skipped in nested configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == "image"
    attr.value.ir_type == "String"
    not regex.match(".*@sha256:[a-fA-F0-9]+.*", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Container image is not pinned with a cryptographic digest. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    lower(attr.name) == url_attr_names[_]
    not has_integrity_attr(node)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Artifact is downloaded without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == "checksum_algorithm"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "none"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Checksum algorithm is set to none. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == "integrity_check"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "disabled"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity check is disabled. (CWE-353)"
    }
}