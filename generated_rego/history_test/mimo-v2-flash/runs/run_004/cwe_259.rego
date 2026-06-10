package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    # Gather all UnitBlocks (scripts, vars, etc.)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check for Variables (common in Ansible vars, Chef attributes, etc.)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    # Check if the variable name suggests a password/secret (case-insensitive)
    regex.match("(?i)(password|secret|api[_-]?key|token|credential|passphrase|key)", var.name)

    # Ensure the value is a hardcoded string (not a reference or function call)
    var.value.ir_type == "String"
    not glitch_lib.traverse_var(var.value)

    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Password (CWE-259) - Avoid hardcoding credentials in IaC scripts."
    }
}

Glitch_Analysis[result] {
    # Gather all UnitBlocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check for Attributes (common in Ansible tasks, Chef resources, etc.)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    # Check if the attribute name suggests a password/secret (case-insensitive)
    regex.match("(?i)(password|secret|api[_-]?key|token|credential|passphrase|key)", attr.name)

    # Ensure the value is a hardcoded string
    attr.value.ir_type == "String"
    not glitch_lib.traverse_var(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password (CWE-259) - Avoid hardcoding credentials in IaC scripts."
    }
}

Glitch_Analysis[result] {
    # Gather all UnitBlocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check AtomicUnits (resources) for password attributes
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check attributes within the atomic unit
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check if the attribute name suggests a password/secret
    regex.match("(?i)(password|secret|api[_-]?key|token|credential|passphrase|key)", attr.name)

    # Ensure the value is a hardcoded string
    attr.value.ir_type == "String"
    not glitch_lib.traverse_var(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password (CWE-259) - Avoid hardcoding credentials in IaC scripts."
    }
}