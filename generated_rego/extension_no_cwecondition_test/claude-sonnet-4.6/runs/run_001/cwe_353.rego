package glitch

import data.glitch_lib

integrity_attr_names := {"checksum", "sha256", "sha512", "sha1", "md5", "hash", "integrity", "digest"}

download_resource_types := {"remote_file", "remote_directory", "archive", "get_url"}

source_attr_names := {"source", "url", "src", "uri"}

gpgcheck_disabled(val) {
    val.ir_type == "Integer"
    val.value == 0
}

gpgcheck_disabled(val) {
    val.ir_type == "String"
    val.value == "0"
}

gpgcheck_disabled(val) {
    val.ir_type == "Boolean"
    val.value == false
}

has_integrity_attr(attrs) {
    attr := attrs[_]
    lower(attr.name) == integrity_attr_names[_]
}

has_source_attr(attrs) {
    attr := attrs[_]
    lower(attr.name) == source_attr_names[_]
}

has_http_source(attrs) {
    attr := attrs[_]
    lower(attr.name) == source_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(https?|ftp)://", attr.value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "gpgcheck"
    gpgcheck_disabled(entry.value)
    result := {
        "type": "sec_no_int_check",
        "element": entry.key,
        "path": parent.path,
        "description": "Missing integrity check - gpgcheck is disabled, repository integrity is not verified. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    lower(attr.name) == "gpgcheck"
    gpgcheck_disabled(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing integrity check - gpgcheck is disabled, package integrity is not verified. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == download_resource_types[_]
    has_source_attr(node.attributes)
    not has_integrity_attr(node.attributes)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check - Resource downloads file without checksum verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    has_http_source(node.attributes)
    not has_integrity_attr(node.attributes)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing integrity check - Resource downloads from URL without checksum verification. (CWE-353)"
    }
}