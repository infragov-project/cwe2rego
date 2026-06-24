package glitch

import data.glitch_lib

# Regex pattern for over-privilege values in any string context
over_privilege_pattern = `(?i)(^root$|^root@|^@root|[\s"']root@|root[/"'\s]|(^|\s)admin(istrator)?[\s"']|^\*$|:\*$|fullaccess|poweruser)`

# Detect over-privilege in string values by traversing all leaf nodes
check_over_privilege(node) {
    glitch_lib.traverse(node, over_privilege_pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Collect all attributes from the entire subtree
    walk(parent, [_, element])
    element.ir_type == "Attribute"

    # Check if value contains over-privileged patterns
    check_over_privilege(element.value)

    result := {
        "type": "sec_def_admin",
        "element": element,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - The configuration grants excessive privileges, such as root or admin user execution context. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Collect all variables from the entire subtree
    walk(parent, [_, element])
    element.ir_type == "Variable"

    # Check if value contains over-privileged patterns
    check_over_privilege(element.value)

    result := {
        "type": "sec_def_admin",
        "element": element,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - The configuration grants excessive privileges, such as root or admin user execution context. (CWE-250)"
    }
}