package glitch

import data.glitch_lib

credential_pattern := "(?i)(password|passwd|pwd|passphrase|pass|secret|credential)"
excluded_pattern := "(?i)secret_key"

is_credential_field(name) {
    regex.match(credential_pattern, name)
    not regex.match(excluded_pattern, name)
}

is_empty_string(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
}

Glitch_Analysis[result] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, kv])
    kv.ir_type == "Variable"
    is_credential_field(kv.name)
    is_empty_string(kv.value)
    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": ub.path,
        "description": "Empty password in configuration - Credential fields should not have empty or blank values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, attr])
    attr.ir_type == "Attribute"
    is_credential_field(attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": ub.path,
        "description": "Empty password in configuration - Credential fields should not have empty or blank values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
    walk(ub, [_, attr])
    attr.ir_type == "Attribute"
    is_credential_field(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    walk(ub, [_, def_attr])
    def_attr.ir_type == "Attribute"
    def_attr.name == arg.value
    is_empty_string(def_attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": ub.path,
        "description": "Empty password in configuration - Credential fields should not have empty or blank values. (CWE-258)"
    }
}