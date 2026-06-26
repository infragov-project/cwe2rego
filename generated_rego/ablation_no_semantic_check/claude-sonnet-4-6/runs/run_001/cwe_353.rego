package glitch

import data.glitch_lib

ssl_verify_attrs := {"validate_certs", "verify_ssl", "ssl_verify"}
ssl_skip_attrs := {"tls_skip_verify", "skip_tls_verify", "no_check_certificate", "allow_insecure", "insecure"}
checksum_verify_attrs := {"verify_checksum", "gpg_check", "repo_gpgcheck"}
checksum_skip_attrs := {"skip_checksum", "disable_gpg_check"}
download_url_attrs := {"url", "src", "download_url", "remote_src"}
integrity_check_attrs := {"checksum", "hash", "sha256", "sha512", "md5", "digest", "integrity"}

has_integrity_attr(attrs) {
    attr := attrs[_]
    attr.name == integrity_check_attrs[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ssl_verify_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - TLS/SSL verification is disabled, allowing tampered data to be accepted. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ssl_skip_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - TLS/SSL verification is skipped, allowing tampered data to be accepted. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == checksum_verify_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Checksum or GPG verification is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == checksum_verify_attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Checksum or GPG verification is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == checksum_skip_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Checksum verification is explicitly skipped. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "checksum"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "none"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Checksum is explicitly set to 'none'. (CWE-353)"
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
        "description": "Missing Support for Integrity Check - Container image is not pinned to an immutable content digest (@sha256:). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    url_attr := attrs[_]
    url_attr.name == download_url_attrs[_]
    url_attr.value.ir_type == "String"
    regex.match("(?i)^https?://", url_attr.value.value)
    not has_integrity_attr(attrs)
    result := {
        "type": "sec_no_int_check",
        "element": url_attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Remote file download without checksum or hash verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(curl|wget)[^|]*\\|[^|]*(bash|sh|python|ruby|perl)", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Remote script piped directly to shell without integrity verification. (CWE-353)"
    }
}