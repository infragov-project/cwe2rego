package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    url_attributes := {"url", "endpoint", "address", "host", "uri"}
    attr.name in url_attributes

    attr.value.ir_type == "String"
    regex.match("^(http|ftp|smtp|telnet)://", attr.value.value)

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Use of unencrypted protocols for sensitive data transmission (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    encryption_flags := {"enable_https", "ssl_enforced", "require_secure_transfer", "use_ssl", "encryption_enabled"}
    attr.name in encryption_flags

    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Encryption explicitly disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    disable_tls_flags := {"disable_tls", "ssl_disabled"}
    attr.name in disable_tls_flags

    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - TLS explicitly disabled (CWE-319)"
    }
}