package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(gpg_check|signature_check|repo_gpgcheck|checksum_enabled|verify_signature|validate_content|data_validation|signature_verification|integrity_check|content_trust|image_signing|cosign_verify|verify|checksum_validation|enable_checksum|data_integrity)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - An integrity check attribute is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(skip_checksum|disable_checksum|no_verify|insecure|unsafe|allow_unsigned|skip_gpg_check|allow_unverified|skip_integrity_check|allow_insecure_images|tofu|trust_on_first_use|disable_content_type_verification|skip_validation)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - A security bypass attribute is explicitly enabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(checksum|integrity|signature|verification|validation|gpg)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(none|disabled|false|off|no)$", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - An integrity-related attribute is set to none or disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^image$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i):(latest|stable|edge|master|main|current|release|dev|nightly|snapshot)$", attr.value.value)
    not regex.match("@sha256:[a-fA-F0-9]+", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Container image uses a mutable tag without a digest pin. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(url|source|src|download|fetch|uri|remote_url|download_url)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(http|ftp)://", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing support for integrity check - Resource is fetched over an insecure protocol without integrity verification. (CWE-353)"
    }
}