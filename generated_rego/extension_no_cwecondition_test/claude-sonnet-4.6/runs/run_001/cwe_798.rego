package glitch

import data.glitch_lib

is_credential_name(name) {
    regex.match("(?i)(password|passwd|pwd|passphrase|private_key|api_key|apikey|access_key|auth_token|keystore|truststore|credential|token)", name)
}

is_credential_name(name) {
    regex.match("(?i)secret", name)
    not regex.match("(?i)secret[_-]*(file|path|xml|json|yaml|dir|url|uri)", name)
}

is_credential_name(name) {
    regex.match("(?i)\\bkey\\b", name)
}

is_credential_name(name) {
    regex.match("(?i)\\buser(name)?\\b", name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match("^\\$\\{.*\\}$", value.value)
    not regex.match("^\\{\\{.*\\}\\}$", value.value)
    not regex.match("^\\$\\(.*\\)$", value.value)
    not regex.match("(?i)^[a-zA-Z]+=.+,[a-zA-Z]+=", value.value)
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
        "description": "Use of hard-coded credentials - Hard-coded credentials such as passwords or cryptographic keys should not be used in IaC scripts. (CWE-798)"
    }
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
        "description": "Use of hard-coded credentials - Hard-coded credentials such as passwords or cryptographic keys should not be used in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_credential_name(entry.key.value)
    is_hardcoded_string(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Hard-coded credentials such as passwords or cryptographic keys should not be used in IaC scripts. (CWE-798)"
    }
}