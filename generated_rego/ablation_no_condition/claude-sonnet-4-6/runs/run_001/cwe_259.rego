package glitch

import data.glitch_lib

password_pattern := "(?i).*(password|passwd|pwd|secret|credential|passphrase|pass_phrase|private_key|api_secret|auth_token|access_token|secret_key|sha512_password|\\bkey\\b).*"

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match("^\\$\\{.*\\}$", value.value)
    not regex.match("^\\$\\(.*\\)$", value.value)
    not regex.match("^\\$[a-zA-Z_][a-zA-Z0-9_]*$", value.value)
    not regex.match("^\\{\\{.*\\}\\}$", value.value)
    not regex.match("^%\\{.*\\}$", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_pattern, attr.name)
    is_hardcoded_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Hard-coded passwords in IaC scripts may be used by attackers to gain unauthorized access. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    regex.match(password_pattern, variable.name)
    is_hardcoded_string(variable.value)
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded password - Hard-coded passwords in IaC scripts may be used by attackers to gain unauthorized access. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    regex.match(password_pattern, entry.key.value)
    is_hardcoded_string(entry.value)
    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Hard-coded passwords in IaC scripts may be used by attackers to gain unauthorized access. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match("(?i).*(password|passwd|pwd|secret|credential|passphrase|pass_phrase|private_key|api_secret|auth_token|access_token|secret_key|sha512_password)\\s*=\\s*.+", node.value)
    not regex.match("(?i).*(password|passwd|pwd|secret|credential|passphrase|pass_phrase|private_key|api_secret|auth_token|access_token|secret_key|sha512_password)\\s*=\\s*(\\$\\{|\\$\\(|\\{\\{|%\\{)", node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Hard-coded passwords in IaC scripts may be used by attackers to gain unauthorized access. (CWE-259)"
    }
}