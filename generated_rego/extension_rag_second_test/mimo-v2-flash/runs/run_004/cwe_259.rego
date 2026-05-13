package glitch

import data.glitch_lib

sensitive_key_keywords := {"password", "pass", "pwd", "secret", "token", "api_key", "secret_key", "connection_string", "basic_auth"}

password_assignment_regex := "(?i).*\\bpassword\\b=.*"

contains_key_keyword(name) {
    keyword := sensitive_key_keywords[_]
    regex.match(sprintf("(?i).*\\b%s\\b", [keyword]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    kv.key.ir_type == "String"
    lower_key := lower(kv.key.value)
    contains_key_keyword(lower_key)
    kv.value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": kv,
        "path": parent.path,
        "description": "Hardcoded password in IaC script - Avoid using hard-coded passwords. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    lower_name := lower(node.name)
    contains_key_keyword(lower_name)
    node.value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded password in IaC script - Avoid using hard-coded passwords. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    lower_name := lower(node.name)
    contains_key_keyword(lower_name)
    node.value.ir_type == "String"
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded password in IaC script - Avoid using hard-coded passwords. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match(password_assignment_regex, node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded password in IaC script - Avoid using hard-coded passwords. (CWE-259)"
    }
}