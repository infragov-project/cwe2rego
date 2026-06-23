package glitch

import data.glitch_lib

is_password_key(name) {
    regex.match("(?i).*(password|passwd|pwd|pass(?:wd|phrase|key)?|activation.?key|credential)", name)
}

is_empty_value(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    is_password_key(variable.name)
    is_empty_value(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration - A password field is assigned an empty value, effectively disabling authentication. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_key(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - A password field is assigned an empty value, effectively disabling authentication. (CWE-258)"
    }
}