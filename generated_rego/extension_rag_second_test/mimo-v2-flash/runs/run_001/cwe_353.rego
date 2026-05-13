package glitch

import data.glitch_lib

insecure_protocols := {"http", "ftp", "tcp", "udp"}

check_insecure_protocol(value) {
    value.ir_type == "String"
    regex.match("(?i)^(http|ftp|tcp|udp)://", value.value)
}

check_insecure_protocol(value) {
    value.ir_type == "Sum"
    walk(value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)^(http|ftp|tcp|udp)://", node.value)
}

check_disabled_integrity(attr) {
    attr.name == "validate_certs"
    attr.value.ir_type == "String"
    lower_val := lower(attr.value.value)
    contains(lower_val, "no")
}

check_disabled_integrity(attr) {
    attr.name == "validate_certs"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

check_disabled_integrity(attr) {
    attr.name == "gpgcheck"
    attr.value.ir_type == "Integer"
    attr.value.value == 0
}

check_disabled_integrity(attr) {
    attr.name == "gpgcheck"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "url" or node.name == "source" or node.name == "baseurl" or node.name == "mirrorlist"
    check_insecure_protocol(node.value)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": sprintf("Insecure protocol detected in '%s'. (CWE-353)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    check_disabled_integrity(node)
    
    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": sprintf("Integrity check disabled in '%s'. (CWE-353)", [node.name])
    }
}