package glitch

import data.glitch_lib
import future.keywords.in
import future.keywords.if
import future.keywords.contains

check_disabled_integrity(val) {
    val.ir_type == "Boolean"
    val.value == false
} else {
    val.ir_type == "Integer"
    val.value == 0
} else {
    val.ir_type == "String"
    regex.match("^(?i)(false|no|disable|disabled|off|0)$", val.value)
}

integrity_check_attrs := {
    "check_signature",
    "gpgcheck",
    "gpg_check",
    "verify_checksum",
    "checksum_verify",
    "verify_signature",
    "signature_check",
    "enforce_checksum",
    "checksum_enforce",
    "validate_checksum",
    "checksum",
    "sha",
    "sha256",
    "sha512",
    "md5",
    "verify",
    "verify_ssl",
    "ssl_verify",
    "strict_host_key_checking",
    "verify_peer",
    "verify_host",
    "hash",
    "digest",
    "checksums",
    "checksum_url",
    "source_hash",
    "checksum_value"
}

download_types := {
    "get_url",
    "wget",
    "curl",
    "download",
    "fetch",
    "uri",
    "win_get_url",
    "get",
    "remote_file",
    "file",
    "package",
    "archive",
    "unarchive",
    "http_request"
}

is_http_url(str) {
    regex.match("^https?://", str)
}

url_indicator_patterns := {
    "http://",
    "https://",
    "url",
    "uri",
    "source",
    "download",
    "mirror",
    "repo",
    "repository"
}

has_url_reference(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    is_http_url(n.value)
}

has_url_reference(node) {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
    contains(lower(n.value), url_indicator_patterns[_])
}

find_any_atomic_units(root) = units {
    units := {u |
        walk(root, [_, u])
        u.ir_type == "AtomicUnit"
    }
}

find_all_attributes(node) = attrs {
    attrs := {a |
        walk(node, [_, a])
        a.ir_type == "Attribute"
    }
}

has_integrity_attr_value_disabled(node) {
    some attr in find_all_attributes(node)
    integrity_check_attrs[lower(attr.name)]
    check_disabled_integrity(attr.value)
}

has_integrity_attr_present(node) {
    some attr in find_all_attributes(node)
    integrity_check_attrs[lower(attr.name)]
}

is_download_type(node) {
    node.ir_type == "AtomicUnit"
    download_types[lower(node.type)]
}

Glitch_Analysis contains result if {
    walk(input, [_, node])
    is_download_type(node)
    has_url_reference(node)
    not has_integrity_attr_present(node)

    some parent in glitch_lib._gather_parent_unit_blocks
    parent.path != ""

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Download from external URL without integrity verification mechanism (checksum, signature, or hash). (CWE-353)"
    }
}

Glitch_Analysis contains result if {
    walk(input, [_, node])
    is_download_type(node)
    has_url_reference(node)
    has_integrity_attr_value_disabled(node)

    some parent in glitch_lib._gather_parent_unit_blocks
    parent.path != ""

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification explicitly disabled for external download. (CWE-353)"
    }
}

Glitch_Analysis contains result if {
    walk(input, [_, node])
    node.ir_type == "Hash"
    some entry in node.value
    entry.key.ir_type == "String"
    integrity_check_attrs[lower(entry.key.value)]
    check_disabled_integrity(entry.value)

    some parent in glitch_lib._gather_parent_unit_blocks
    parent.path != ""

    result := {
        "type": "sec_no_int_check",
        "element": entry,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification explicitly disabled in configuration. (CWE-353)"
    }
}

Glitch_Analysis contains result if {
    walk(input, [_, node])
    node.ir_type == "Attribute"
    integrity_check_attrs[lower(node.name)]
    check_disabled_integrity(node.value)

    some parent in glitch_lib._gather_parent_unit_blocks
    parent.path != ""

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification explicitly disabled in attribute. (CWE-353)"
    }
}