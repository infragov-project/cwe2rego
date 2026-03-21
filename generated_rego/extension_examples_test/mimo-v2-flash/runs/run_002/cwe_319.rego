package glitch

import data.glitch_lib

insecure_protocols := "(?i)^(http://|ftp://|telnet://|ws://|mysql://|postgresql://)"

encryption_disabling_attrs := {"enable_https", "ssl_enforced", "tls_version", "enable_https_traffic_only", "force_https", "validate_certs"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match(insecure_protocols, node.value)
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Use of unencrypted protocol (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.name in encryption_disabling_attrs
    attr.value.ir_type == "String"
    attr.value.value in {"no", "false", "disabled", "none"}
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption explicitly disabled (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.name in encryption_disabling_attrs
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Encryption explicitly disabled (CWE-319)"
    }
}