package glitch

import data.glitch_lib

transfer_keywords := {"transfer", "upload", "download", "sync", "replicate", "push", "pull", "deploy", "publish"}

integrity_keywords := {"checksum", "hash", "digest", "signature", "verify", "validate", "integrity", "md5", "sha", "crc", "sig"}

integrity_fields := {"verify_checksum", "checksum_algorithm", "expected_hash", "digest_method", "signature_header", "secret", "hmac", "payload_hash", "content_trust", "notary", "signed_images", "immutable_tags", "state_checksum", "consistency_check", "etag_validation", "content_md5", "wal_checksum", "page_checksum", "snapshot_verification"}

insecure_protocols := {"ftp", "tftp", "http", "udp", "plain", "legacy", "raw", "socket"}

insecure_flags := {"skip_verification", "ignore_checksum", "no_validate", "disable_integrity", "insecure", "verify_ssl", "ssl_verify", "tls_verify", "validate_certs"}

verify_disabled := {"false", "disabled", "no", "0", "off"}

is_verification_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    lower(value.value) == verify_disabled[_]
} else {
    value.ir_type == "Integer"
    value.value == 0
}

is_insecure_protocol(value) {
    value.ir_type == "String"
    contains(lower(value.value), insecure_protocols[_])
}

name_matches(attr_name, patterns) {
    lower(attr_name) == patterns[_]
} else {
    contains(lower(attr_name), patterns[_])
}

has_integrity_check(value) {
    value.ir_type == "String"
    name_matches(value.value, integrity_keywords)
} else {
    walk(value, [_, v])
    v.ir_type == "KeyValue"
    name_matches(v.name, integrity_fields)
}

is_data_transfer_type(type_str) {
    contains(lower(type_str), transfer_keywords[_])
}

has_integrity_attribute(attrs) {
    attr := attrs[_]
    name_matches(attr.name, integrity_fields)
} else {
    attr := attrs[_]
    walk(attr, [_, v])
    v.ir_type == "KeyValue"
    name_matches(v.name, integrity_fields)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_data_transfer_type(node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    name_matches(attr.name, {"protocol", "method", "transport", "scheme", "endpoint", "url", "uri"})
    is_insecure_protocol(attr.value)
    not has_integrity_attribute(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Data transmission uses insecure protocol without integrity verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_data_transfer_type(node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    name_matches(attr.name, insecure_flags)
    is_verification_disabled(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity verification explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    name_matches(attr.name, {"source", "src", "destination", "dest", "url", "uri", "endpoint", "package", "artifact"})
    attr.value.ir_type == "String"
    not has_integrity_attribute(attrs)
    is_data_transfer_type(node.type)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Data transfer lacks integrity verification mechanism. (CWE-353)"
    }
}