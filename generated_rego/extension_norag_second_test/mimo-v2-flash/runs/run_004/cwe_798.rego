package glitch

import data.glitch_lib

sensitive_keywords := {"password", "secret", "key", "token", "credential", "auth", "access_key", "secret_key", "api_key", "private_key", "client_secret"}

contains_sensitive_keyword(str) {
    keyword := sensitive_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_sensitive_keyword(var.name)
    var.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded secret in IaC - Avoid hard-coding secrets like passwords, keys, or tokens in scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_sensitive_keyword(attr.name)
    attr.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded secret in IaC - Avoid hard-coding secrets like passwords, keys, or tokens in scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    walk(var.value.value, [path, kv])
    kv.key.ir_type == "String"
    kv.value.ir_type == "String"
    contains_sensitive_keyword(kv.key.value)
    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Hard-coded secret in IaC - Avoid hard-coding secrets like passwords, keys, or tokens in scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    walk(attr.value.value, [path, kv])
    kv.key.ir_type == "String"
    kv.value.ir_type == "String"
    contains_sensitive_keyword(kv.key.value)
    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Hard-coded secret in IaC - Avoid hard-coding secrets like passwords, keys, or tokens in scripts. (CWE-798)"
    }
}