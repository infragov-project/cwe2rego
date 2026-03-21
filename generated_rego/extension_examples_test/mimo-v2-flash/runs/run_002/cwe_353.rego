package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "AtomicUnit"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name.ir_type == "String"
    regex.match("(?i)^(validate_certs|gpgcheck)$", attr.name.value)
    attr.value.ir_type == "String"
    regex.match("(?i)^(no|false|disabled|0)$", attr.value.value)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Certificate validation disabled - Missing integrity check for data transmission. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.ir_type == "Variable"
    var.value.ir_type == "Hash"
    hash_pair := var.value.value[_]
    hash_pair.key.ir_type == "String"
    regex.match("(?i)^(gpgcheck)$", hash_pair.key.value)
    hash_pair.value.ir_type == "Integer"
    hash_pair.value.value == 0
    result := {
        "type": "sec_no_int_check",
        "element": var,
        "path": parent.path,
        "description": "GPG signature check disabled - Missing integrity check for package verification. (CWE-353)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.ir_type == "AtomicUnit"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name.ir_type == "String"
    regex.match("(?i)^(source|url|baseurl)$", attr.name.value)
    attr.value.ir_type == "String"
    regex.match("(?i)^http://", attr.value.value)
    not has_secure_counterpart(attr, node)
    result := {
        "type": "sec_no_int_check",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol (HTTP) used for data transmission without integrity verification. (CWE-353)"
    }
}

has_secure_counterpart(attr, node) {
    attrs := glitch_lib.all_attributes(node)
    other_attr := attrs[_]
    other_attr != attr
    other_attr.name.ir_type == "String"
    regex.match("(?i)^(validate_certs|ssl_enabled|require_secure_transport)$", other_attr.name.value)
    other_attr.value.ir_type == "Boolean"
    other_attr.value.value == true
}

has_secure_counterpart(attr, node) {
    attrs := glitch_lib.all_attributes(node)
    other_attr := attrs[_]
    other_attr != attr
    other_attr.name.ir_type == "String"
    regex.match("(?i)^(ssl_mode)$", other_attr.name.value)
    other_attr.value.ir_type == "String"
    other_attr.value.value == "enabled"
}