package glitch

import data.glitch_lib

password_keywords := {"password", "secret", "token", "credential", "passwd", "pwd"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    lower_name := lower(variable.name)
    contains_password_keyword := false
    some kw
    kw := password_keywords[_]
    contains(lower_name, kw)
    contains_password_keyword := true
    variable.value.ir_type == "String"
    value := variable.value.value
    not contains(value, "$6$")  # Exclude common hash patterns like SHA512
    contains_password_keyword
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded credentials in IaC scripts violate CWE-259. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    lower_name := lower(attribute.name)
    contains_password_keyword := false
    some kw
    kw := password_keywords[_]
    contains(lower_name, kw)
    contains_password_keyword := true
    attribute.value.ir_type == "String"
    value := attribute.value.value
    not contains(value, "$6$")  # Exclude common hash patterns like SHA512
    contains_password_keyword
    result := {
        "type": "sec_hard_pass",
        "element": attribute,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded credentials in IaC scripts violate CWE-259. (CWE-259)"
    }
}