package glitch

import data.glitch_lib

is_false_value(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    {"no", "false", "0"}[lower(value.value)]
} else {
    value.ir_type == "Integer"
    value.value == 0
}

check_insecure_protocol(value) {
    value.ir_type == "String"
    protocol_value := lower(value.value)
    insecure_protocols := {"http", "ftp", "tcp", "udp"}
    insecure_protocols[protocol_value]
}

check_insecure_url(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    url_value := lower(n.value)
    insecure_url_protocols := {"http://", "ftp://"}
    some protocol
    insecure_url_protocols[protocol]
    startswith(url_value, protocol)
} else {
    value.ir_type == "Sum"
    walk(value, [_, n])
    n.ir_type == "String"
    url_value := lower(n.value)
    insecure_url_protocols := {"http://", "ftp://"}
    some protocol
    insecure_url_protocols[protocol]
    startswith(url_value, protocol)
}

check_validate_certs(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    lower(n.value) in {"no", "false", "0"}
} else {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "Integer"
    value.value == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.name == "gpgcheck"
    is_false_value(node.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - GPG signature check disabled (gpgcheck=0). (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == "gpgcheck"
    is_false_value(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - GPG signature check disabled in variable. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    {"url", "source"}[attr.name]
    check_insecure_url(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Resource uses insecure URL without integrity verification mechanisms. (CWE-353)"
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
    check_insecure_protocol(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Resource uses insecure protocol without integrity verification mechanisms. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "get_url"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "validate_certs"
    check_validate_certs(attr.value)

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Certificate validation disabled in get_url. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "remote_file"
    attrs := glitch_lib.all_attributes(node)
    not attrs[_].name == "checksum"
    not attrs[_].name == "verify"

    result := {
        "type": "sec_no_int_check",
        "element": node,
        "path": parent.path,
        "description": "Missing Support for Integrity Check - Remote file resource without checksum or verification. (CWE-353)"
    }
}