package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "enable_versioning"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Missing data integrity verification in storage - enable_versioning is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "protocol"
    attr.value.ir_type == "String"
    regex.match("^(HTTP|FTP|TCP)$", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure or unverified communication protocol - protocol is set to unencrypted value. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "ssl_mode"
    attr.value.ir_type == "String"
    regex.match("^(DISABLED|ALLOW)$", attr.value.value)

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure or unverified communication protocol - ssl_mode is set to insecure value. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "verify_tls"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure or unverified communication protocol - verify_tls is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "enforce_https"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure or unverified communication protocol - enforce_https is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "secure_boot"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Lack of firmware integrity checks - secure_boot is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "tpm_enabled"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Lack of firmware integrity checks - tpm_enabled is disabled. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "request_validation"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Absence of API request validation - request_validation is disabled. (CWE-353)"
    }
}