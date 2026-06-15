package glitch

import data.glitch_lib

permissive_value(value) {
    value.ir_type == "String"
    regex.match("^(\\*|AdministratorAccess|FullAccess)$", value.value)
} else {
    value.ir_type == "Array"
    some item in value.value
    item.ir_type == "String"
    regex.match("^(\\*|AdministratorAccess|FullAccess)$", item.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "Action" or attr.name == "Resource" or attr.name == "permissions"
    permissive_value(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy - The policy grants excessive privileges (e.g., wildcard or admin access). (CWE-250)"
    }
}