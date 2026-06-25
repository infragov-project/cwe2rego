package glitch

import data.glitch_lib

is_unrestricted_ip(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_unrestricted_ip(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The use of 0.0.0.0 exposes the service to every possible network, allowing connections from any interface. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_unrestricted_ip(v.value)

    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The use of 0.0.0.0 exposes the service to every possible network, allowing connections from any interface. (CWE-1327)"
    }
}