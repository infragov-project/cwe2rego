package glitch

import data.glitch_lib

cred_keywords := {"password", "pass", "pwd", "secret", "credential", "auth", "key", "token", "apikey", "private_key", "certificate", "ssh_key", "auth_token"}

check_hardcoded_string(node) {
    node.ir_type == "String"
    node.value != ""
    not startswith(node.value, "$")
    not startswith(node.value, "{{")
    not startswith(node.value, "var.")
    not startswith(node.value, "env.")
    not startswith(node.value, "lookup(")
    not startswith(node.value, "secrets_manager")
}

check_hardcoded_value(node) {
    check_hardcoded_string(node)
}

check_hardcoded_value(node) {
    node.ir_type == "Hash"
    walk(node, [path, leaf])
    leaf.ir_type == "String"
    check_hardcoded_string(leaf)
}

check_hardcoded_value(node) {
    node.ir_type == "Array"
    walk(node, [path, leaf])
    leaf.ir_type == "String"
    check_hardcoded_string(leaf)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    regex.match(sprintf("(?i).*\\b(%s)\\b.*", [concat("|", cred_keywords)]), attr.name)
    
    check_hardcoded_value(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding sensitive authentication data directly in source code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.name == "user_data"
    attr.value.ir_type == "String"
    regex.match("(?i).*(password|passwd|pwd|secret|token|key|credential|auth|username|user|api_key|api_key|apikey).*", attr.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Embedded configuration files contain credential patterns. (CWE-798)"
    }
}