package glitch

import data.glitch_lib

credential_name_pattern := "(?i).*(password|passwd|pwd|secret|credential|token|api[_\\-]?key|private[_\\-]?key|auth[_\\-]?key|access[_\\-]?key|encryption[_\\-]?key|passphrase|keystore|truststore|\\bkey\\b|\\busername\\b|\\buser\\b).*"

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not startswith(value.value, "/")
    not glitch_lib.has_variable_reference(value)
    not regex.match("^[a-zA-Z][a-zA-Z0-9]*=.+(,[a-zA-Z][a-zA-Z0-9]*=.+)+$", value.value)
}

all_unit_blocks[ub] {
    ub := input
    ub.ir_type == "UnitBlock"
    ub.path != ""
}

all_unit_blocks[ub] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
}

Glitch_Analysis[result] {
    parent := all_unit_blocks[_]
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(credential_name_pattern, attr.name)
    is_hardcoded_string(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials such as passwords, keys, and tokens should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := all_unit_blocks[_]
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(credential_name_pattern, var.name)
    is_hardcoded_string(var.value)

    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials such as passwords, keys, and tokens should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := all_unit_blocks[_]
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    regex.match(credential_name_pattern, entry.key.value)
    is_hardcoded_string(entry.value)

    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials such as passwords, keys, and tokens should not be hard-coded in IaC scripts. (CWE-798)"
    }
}