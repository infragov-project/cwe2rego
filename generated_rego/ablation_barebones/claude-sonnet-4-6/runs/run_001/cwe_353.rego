package glitch

import data.glitch_lib

has_checksum_attr(attrs) {
    attr := attrs[_]
    regex.match("(?i)^(checksum|sha256|sha512|sha1|md5|hash|digest|integrity|verify)$", attr.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)^(gpg_?check|integrity_?check|checksum_?check|verify_?checksum)$", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity/checksum verification is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)^(gpg_?check|integrity_?check|checksum_?check|verify_?checksum)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity/checksum verification is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match("(?i)^(disable_?gpg_?check|skip_?checksum|no_?checksum|ignore_?checksum|disable_?checksum|disable_?integrity)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Integrity/checksum verification is explicitly disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    regex.match("(?i)(get_url|remote_file|download|fetch|retrieve)", node.type)

    attrs := glitch_lib.all_attributes(node)
    not has_checksum_attr(attrs)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Download resource does not specify a checksum or hash for integrity verification. (CWE-353)"
    }
}