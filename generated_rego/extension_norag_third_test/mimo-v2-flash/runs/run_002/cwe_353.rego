package glitch

import data.glitch_lib

integrity_keywords := {"checksum", "integrity", "gpgcheck", "validate_certs", "ssl", "tls", "signature", "verify", "checksum_algorithm"}
unencrypted_attrs := {"url", "source", "baseurl", "mirrorlist"}
unencrypted_protocols := {"http://", "ftp://", "telnet://"}

is_disabled_value(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    regex.match("(?i)^(no|off|disabled|false|0)$", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
}

has_unencrypted_protocol(value) {
    value.ir_type == "String"
    regex.match("(?i)^(http|ftp|telnet)://", value.value)
} else {
    value.ir_type == "Sum"
    glitch_lib.traverse(value, "(?i)^(http|ftp|telnet)://")
}

check_integrity_violation_attr(node) {
    node.ir_type == "Attribute"
    glitch_lib.contains(node.name, integrity_keywords[_])
    is_disabled_value(node.value)
}

check_integrity_violation_attr(node) {
    node.ir_type == "Attribute"
    glitch_lib.contains(node.name, unencrypted_attrs[_])
    has_unencrypted_protocol(node.value)
}

check_integrity_violation_var(node) {
    node.ir_type == "Variable"
    glitch_lib.contains(node.name, integrity_keywords[_])
    is_disabled_value(node.value)
}

check_integrity_violation_var(node) {
    node.ir_type == "Variable"
    glitch_lib.contains(node.name, unencrypted_attrs[_])
    has_unencrypted_protocol(node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := {n |
        walk(parent, [path, n])
        n.ir_type == "Attribute" or n.ir_type == "Variable"
    }
    node := all_nodes[_]
    check_integrity_violation_attr(node)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing or disabled integrity check in infrastructure configuration. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := {n |
        walk(parent, [path, n])
        n.ir_type == "Attribute" or n.ir_type == "Variable"
    }
    node := all_nodes[_]
    check_integrity_violation_var(node)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing or disabled integrity check in infrastructure configuration. (CWE-353)"
    }
}