package glitch

import data.glitch_lib

sensitive_keywords = {"password", "secret", "key", "token", "credential", "auth", "access_key", "api_key"}

matches_sensitive_keyword(name) {
    lower_name := lower(name)
    some keyword
    keyword = sensitive_keywords[_]
    glitch_lib.contains(lower_name, keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    matches_sensitive_keyword(var.name)
    var.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credentials - Avoid hard-coding credentials in the code. Use a secret management system instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    matches_sensitive_keyword(attr.name)
    attr.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credentials - Avoid hard-coding credentials in the code. Use a secret management system instead. (CWE-798)"
    }
}