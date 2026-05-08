package glitch

import data.glitch_lib

# Helper rule to detect 0.0.0.0 in any String node within a complex value
is_unrestricted_bind(val) {
    walk(val, [path, node])
    node.ir_type == "String"
    regex.match("(?i)0\\.0\\.0\\.0", node.value)
}

# Rule 1: Detect in Variables (e.g., Chef attributes, Ansible vars)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check variables defined in the block
    var := parent.variables[_]

    # Check if the variable name suggests it's a binding address
    walk(var.name, [_, n])
    n.ir_type == "String"
    regex.match("(?i)(bind|listen|host|ip|address)", n.value)

    # Check if the value contains 0.0.0.0
    is_unrestricted_bind(var.value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) in variable configuration. (CWE-1327)"
    }
}

# Rule 2: Detect in Atomic Unit Attributes (e.g., resource parameters)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check if the attribute name suggests it's a binding address
    walk(attr.name, [_, n])
    n.ir_type == "String"
    regex.match("(?i)(bind|listen|host|ip|address)", n.value)

    # Check if the value contains 0.0.0.0
    is_unrestricted_bind(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) in resource attribute. (CWE-1327)"
    }
}