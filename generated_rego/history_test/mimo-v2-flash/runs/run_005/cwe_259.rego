package glitch

import data.glitch_lib

sensitive_keywords = {"password", "secret", "token", "api_key", "credential", "auth_key", "admin_password", "master_key", "connection_string", "key", "passwd"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables in the parent
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable name contains sensitive keyword and value is a static string
    contains_sensitive_name(var.name)
    var.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded password detected in variable. Avoid using static passwords in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the parent
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if attribute name contains sensitive keyword and value is a static string
    contains_sensitive_name(attr.name)
    attr.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password detected in attribute. Avoid using static passwords in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for sensitive keys in Hash values (nested passwords)
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    # Get all key-value pairs in the hash
    pair := node.value[_]
    key := pair.key
    value := pair.value
    
    # Check if key is a string and contains sensitive keyword, and value is a string
    key.ir_type == "String"
    contains_sensitive_name(key.value)
    value.ir_type == "String"
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password detected in configuration. Avoid using static passwords in code. (CWE-259)"
    }
}

contains_sensitive_name(name) {
    # Check if name contains any of the sensitive keywords
    some keyword
    sensitive_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}