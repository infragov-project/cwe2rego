package glitch

import data.glitch_lib

bypass_integrity_names := {
    "skip_checksum", "skip_verify", "no_verify", "disable_integrity",
    "allow_insecure", "insecure_skip", "skip_signature", "bypass_validation",
    "allow_unauthenticated"
}

verify_integrity_names := {
    "verify", "verify_checksum", "validate", "validate_certs",
    "enable_integrity_checking", "ssl_verify", "tls_verify",
    "get_checksum"
}

gpg_check_names := {"gpgcheck", "repo_gpgcheck"}

checksum_field_names := {
    "checksum", "hash", "sha256", "md5sum", "source_hash",
    "checksum_sha256", "checksum_crc32", "image_digest", "content_digest",
    "digest", "gpg_key", "signature"
}

has_integrity_attr(attrs) {
    attr := attrs[_]
    lower(attr.name) == checksum_field_names[_]
    attr.value.ir_type == "String"
    v := lower(attr.value.value)
    v != ""
    v != "none"
    v != "disabled"
    v != "false"
    v != "null"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == bypass_integrity_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - An integrity bypass or skip flag is explicitly enabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == bypass_integrity_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"true", "yes", "1"}[_]
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - An integrity bypass or skip flag is explicitly enabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == verify_integrity_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity or certificate validation is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == verify_integrity_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"false", "no", "0"}[_]
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity or certificate validation is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == checksum_field_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Checksum attribute is explicitly set to false. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == checksum_field_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"", "none", "disabled", "false", "null"}[_]
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Checksum or hash attribute is set to an empty or ineffective value. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == checksum_field_names[_]
    attr.value.ir_type == "Null"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Checksum or hash attribute is explicitly set to null. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == gpg_check_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - GPG/package signature verification is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == gpg_check_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - GPG/package signature verification is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "checksum_mode"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "disabled"
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Storage/object checksum mode is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(url|source|endpoint|download|fetch|remote|repo|repository)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp)://", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Insecure protocol (HTTP/FTP) used for data retrieval without integrity guarantees. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "image"
    attr.value.ir_type == "String"
    regex.match("(?i):latest$", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Container image uses mutable ':latest' tag without cryptographic digest pinning. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    regex.match("(?i)(get_url|remote_file|download|fetch|http_request)", node.type)
    node_attrs := glitch_lib.all_attributes(node)
    not has_integrity_attr(node_attrs)
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Remote content download/fetch operation lacks checksum or hash validation. (CWE-353)"
    }
}