package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check variables (common in Ansible vars files)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    var.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Unrestricted network bind address - Binding services to 0.0.0.0 exposes them to all network interfaces. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check attributes (common in Ansible tasks)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted network bind address - Binding services to 0.0.0.0 exposes them to all network interfaces. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check Hash values in Variables (common in Chef)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    walk(var.value, [path, n])
    n.ir_type == "String"
    n.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": n,
        "path": parent.path,
        "description": "Unrestricted network bind address - Binding services to 0.0.0.0 exposes them to all network interfaces. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check Atomic Units (common in Puppet)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "String"
    n.value == "0.0.0.0"
    result := {
        "type": "sec_invalid_bind",
        "element": n,
        "path": parent.path,
        "description": "Unrestricted network bind address - Binding services to 0.0.0.0 exposes them to all network interfaces. (CWE-284)"
    }
}