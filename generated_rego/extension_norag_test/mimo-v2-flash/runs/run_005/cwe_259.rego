package glitch

import data.glitch_lib

password_keywords := {"password", "secret", "passwd", "pwd", "token", "key", "credential", "auth", "access_key", "secret_key", "admin_password", "db_password", "api_key", "truststore_password", "keystore_password"}

contains_password_keyword(str) {
    kw := password_keywords[_]
    regex.match(sprintf("(?i)\\b%s\\b", [kw]), str)
}

is_hardcoded_password(node) {
    node.ir_type == "String"
    node.value != ""
    not regex.match(".*\\$\\{.*\\}.*", node.value)
    not regex.match(".*!.*", node.value)
    not regex.match(".*lookup\\(.*\\).*", node.value)
    not regex.match(".*env.*", node.value)
}

find_hardcoded_passwords_in_value(value) = passwords {
    passwords := {password_node |
        walk(value, [path, node])
        node.ir_type == "Hash"
        pair := node.value[_]
        pair.key.ir_type == "String"
        contains_password_keyword(pair.key.value)
        pair.value.ir_type == "String"
        is_hardcoded_password(pair.value)
        password_node := pair.value
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables
    var := glitch_lib.all_variables(parent)[_]
    
    # Case 1: Variable name contains password keyword and value is hardcoded string
    contains_password_keyword(var.name)
    var.value.ir_type == "String"
    is_hardcoded_password(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var.value,
        "path": parent.path,
        "description": "Hard-coded password or secret in configuration - Avoid using hard-coded passwords or secrets. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for nested passwords
    var := glitch_lib.all_variables(parent)[_]
    passwords := find_hardcoded_passwords_in_value(var.value)
    password := passwords[_]
    result := {
        "type": "sec_hard_pass",
        "element": password,
        "path": parent.path,
        "description": "Hard-coded password or secret in configuration - Avoid using hard-coded passwords or secrets. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes
    attr := glitch_lib.all_attributes(parent)[_]
    
    # Case 1: Attribute name contains password keyword and value is hardcoded string
    contains_password_keyword(attr.name)
    attr.value.ir_type == "String"
    is_hardcoded_password(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr.value,
        "path": parent.path,
        "description": "Hard-coded password or secret in configuration - Avoid using hard-coded passwords or secrets. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes for nested passwords
    attr := glitch_lib.all_attributes(parent)[_]
    passwords := find_hardcoded_passwords_in_value(attr.value)
    password := passwords[_]
    result := {
        "type": "sec_hard_pass",
        "element": password,
        "path": parent.path,
        "description": "Hard-coded password or secret in configuration - Avoid using hard-coded passwords or secrets. (CWE-259)"
    }
}