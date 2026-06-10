package glitch

import data.glitch_lib

credential_keywords := {"password", "secret", "token", "key", "credential", "username", "access_key", "secret_key", "api_key", "auth", "client_secret"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    credential_keywords[attr.name]
    attr.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in attribute - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    credential_keywords[var.name]
    var.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential in variable - Avoid using hard-coded credentials. (CWE-798)"
    }
}