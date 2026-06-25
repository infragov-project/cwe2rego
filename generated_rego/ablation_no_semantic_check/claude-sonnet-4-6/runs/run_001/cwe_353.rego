package glitch

import data.glitch_lib

integrity_check_false_attrs := {
    "gpgcheck", "gpg_check", "signature_check", "verify_checksum",
    "verify_hash", "check_integrity", "enable_checksum", "repo_gpgcheck",
    "ssl_verify", "data_integrity", "integrity_check", "replication_checksum",
    "transfer_verification"
}

insecure_true_attrs := {
    "insecure_skip_verify", "tls_skip_verify", "allow_untrusted"
}

url_source_attrs := {
    "source", "url", "remote_url", "download_url", "endpoint", "repository", "mirror"
}

is_insecure_url(value) {
    value.ir_type == "String"
    regex.match("(?i)^(http://|ftp://)", value.value)
}

is_mutable_image_tag(value) {
    value.ir_type == "String"
    not regex.match("@sha256:", value.value)
    regex.match("(?i):(latest|stable|edge|master|main|develop|beta|alpha|release)", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == integrity_check_false_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

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
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == integrity_check_false_attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification is explicitly disabled via integer flag. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == insecure_true_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - TLS or integrity verification is explicitly bypassed. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == url_source_attrs[_]
    is_insecure_url(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure protocol (HTTP/FTP) used for resource retrieval without integrity guarantees. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "image"
    is_mutable_image_tag(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Container image uses a mutable tag without digest pinning. (CWE-353)"
    }
}