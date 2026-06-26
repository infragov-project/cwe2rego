package glitch

import data.glitch_lib

bypass_true_names := {
    "skip_checksum", "disable_verify", "insecure", "skip_verify",
    "allow_unauthenticated", "disable_gpg_check", "no_verify",
    "allow_insecure_downloads"
}

bypass_false_names := {
    "verify_checksum", "validate_checksum", "gpg_check", "gpgcheck",
    "repo_gpgcheck", "signature_verification", "enable_checksum",
    "integrity_check", "checksum_enabled", "message_signing"
}

checksum_attr_names := {
    "checksum", "sha256", "sha512", "md5", "hash",
    "source_code_hash", "content_hash", "code_hash"
}

url_attr_names := {"url", "source", "filename", "src"}

download_resource_types := {"get_url", "remote_file", "archive", "wget"}

has_integrity_attr(attrs) {
    attr := attrs[_]
    attr.name == checksum_attr_names[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == bypass_true_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification is explicitly bypassed. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == bypass_false_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification flag is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == bypass_false_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification flag is disabled (0). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash])
    hash.ir_type == "Hash"
    pair := hash.value[_]
    pair.key.ir_type == "String"
    pair.key.value == bypass_false_names[_]
    pair.value.ir_type == "Integer"
    pair.value.value == 0

    result := {
        "type": "sec_no_int_check",
        "element": pair.value,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity verification flag is disabled in nested configuration (0). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash])
    hash.ir_type == "Hash"
    pair := hash.value[_]
    pair.key.ir_type == "String"
    pair.key.value == bypass_true_names[_]
    pair.value.ir_type == "Boolean"
    pair.value.value == true

    result := {
        "type": "sec_no_int_check",
        "element": pair.value,
        "path": parent.path,
        "description": "Missing support for integrity check - Integrity bypass flag set in nested configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "image"
    attr.value.ir_type == "String"
    not regex.match(".*@sha256:[a-fA-F0-9]+.*", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Container image does not use digest pinning (@sha256:). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"checksum_algorithm", "checksum_mode"}[_]
    attr.value.ir_type == "String"
    upper(attr.value.value) == {"NONE", "DISABLED"}[_]

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Checksum algorithm or mode is set to NONE/DISABLED. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == download_resource_types[_]
    attrs := glitch_lib.all_attributes(node)
    not has_integrity_attr(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Download resource used without checksum verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    trigger_attr := attrs[_]
    trigger_attr.name == url_attr_names[_]
    trigger_attr.value.ir_type == "String"
    regex.match("(?i)^https?://.*", trigger_attr.value.value)
    not has_integrity_attr(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing support for integrity check - Resource fetched from URL without checksum or hash verification. (CWE-353)"
    }
}