package glitch

import data.glitch_lib

credential_key_pattern := "(?i)(?:password|passwd|pwd|secret|api_key|access_key|secret_key|private_key|client_secret|api_token|auth_token|access_token|api_secret|passphrase|credential|master_key|ssh_key|encryption_key|signing_key|client_key)(?:['\\[\\]_.]|$)|(?:^|_)(?:key|token)(?:['\\[\\]_.]|$)"

credential_string_pattern := "(?i)(?:PASSWORD|PASSWD|PWD|SECRET|API_KEY|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CLIENT_SECRET|API_TOKEN|AUTH_TOKEN|ACCESS_TOKEN|API_SECRET|PASSPHRASE|CREDENTIAL|MASTER_KEY|SSH_KEY|ENCRYPTION_KEY|SIGNING_KEY|CLIENT_KEY|KEY|TOKEN)[=:]\\s*\\S+"

is_hardcoded_string(v) {
    v.ir_type == "String"
    count(v.value) > 0
}

Glitch_Analysis[result] {
    node := walk(input)[_]
    node.ir_type == "Variable"
    regex.match(credential_key_pattern, node.name)
    is_hardcoded_string(node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hard-coding passwords or secrets in the code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    node := walk(input)[_]
    node.ir_type == "Attribute"
    regex.match(credential_key_pattern, node.name)
    is_hardcoded_string(node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hard-coding passwords or secrets in the code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    node := walk(input)[_]
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.value.ir_type == "String"
    regex.match(credential_key_pattern, entry.key.value)
    count(entry.value.value) > 0
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    result := {
        "type": "sec_hard_pass",
        "element": entry,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hard-coding passwords or secrets in the code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    node := walk(input)[_]
    node.ir_type == "String"
    regex.match(credential_string_pattern, node.value)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Avoid hard-coding passwords or secrets in the code. (CWE-259)"
    }
}