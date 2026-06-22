package glitch

import data.glitch_lib

verify_attrs := {"gpg_check", "gpg_verify", "verify", "verify_checksum", "ssl_verify", "tls_verify", "verify_ssl", "validate_certs"}

skip_attrs := {"disable_gpg_check", "skip_verify", "no_verify", "insecure", "insecure_skip_tls_verify", "allow_insecure", "no_hash_check", "skip_integrity"}

url_attrs := {"url", "source", "src", "uri", "baseurl", "repo", "endpoint"}

checksum_attrs := {"checksum", "hash", "sha256", "sha512", "md5", "digest", "content_digest", "image_digest", "gpgkey", "signing_key", "integrity", "expected_hash"}

is_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_disabled(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

is_disabled(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_enabled(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_enabled(value) {
    value.ir_type == "String"
    lower(value.value) == "true"
}

has_integrity_attr(attrs) {
    attr := attrs[_]
    attr.name == checksum_attrs[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == verify_attrs[_]
    is_disabled(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Verification flag is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == skip_attrs[_]
    is_enabled(attr.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Security verification is explicitly skipped or disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == url_attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp|tftp)://", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure protocol used for resource transfer without TLS protection. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "image"
    attr.value.ir_type == "String"
    not regex.match("@sha256:[a-fA-F0-9]+", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Container image referenced without immutable digest pinning (@sha256:). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == url_attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^https://", attr.value.value)
    not has_integrity_attr(attrs)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote resource fetched without checksum or hash verification. (CWE-353)"
    }
}