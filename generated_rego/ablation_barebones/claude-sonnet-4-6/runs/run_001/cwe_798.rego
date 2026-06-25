package glitch

import data.glitch_lib

credential_name_pattern := "(?i).*(password|passwd|pwd|secret|token|api_key|apikey|access_key|accesskey|private_key|privatekey|credential|passphrase|auth_token|auth_key|auth_pass).*"

is_credential_name(name) {
    regex.match(credential_name_pattern, name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    is_credential_name(attr.name)
    is_hardcoded_string(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    is_credential_name(var.name)
    is_hardcoded_string(var.value)

    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"
    }
}