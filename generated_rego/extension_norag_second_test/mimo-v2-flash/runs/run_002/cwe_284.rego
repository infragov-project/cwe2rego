package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := parent.variables[_]
    var.ir_type == "Variable"
    var.value.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0|::/0)$", var.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Unrestricted network binding detected in variable (0.0.0.0 or ::/0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0|::/0)$", attr.value.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network binding detected in attribute (0.0.0.0 or ::/0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_str := pair.key.value
    regex.match("(?i).*bind.*|.*ip.*|.*address.*|.*addr.*", key_str)
    pair.value.ir_type == "String"
    value_str := pair.value.value
    regex.match("^(0\\.0\\.0\\.0|::/0)$", value_str)
    result := {
        "type": "sec_invalid_bind",
        "element": pair.key,
        "path": parent.path,
        "description": "Unrestricted network binding detected in hash (0.0.0.0 or ::/0). (CWE-284)"
    }
}