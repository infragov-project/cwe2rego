package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "pass", "secret", "token", "credential", "auth_key"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_vars := {n | walk(parent, [_, n]); n.ir_type == "Variable"}
    var := all_vars[_]
    lower_name := lower(var.name)
    contains_password_keyword(lower_name)
    
    is_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields must not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := {n | walk(parent, [_, n]); n.ir_type == "Attribute"}
    attr := all_attrs[_]
    lower_name := lower(attr.name)
    contains_password_keyword(lower_name)
    
    is_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields must not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_hashes := {n | walk(parent, [_, n]); n.ir_type == "Hash"}
    hash := all_hashes[_]
    
    some element in hash.value
    element.key.ir_type == "String"
    key_name := element.key.value
    lower_key := lower(key_name)
    contains_password_keyword(lower_key)
    
    is_empty_value(element.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": hash,
        "path": parent.path,
        "description": "Empty password in credential block - Password fields must not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_strings := {n | walk(parent, [_, n]); n.ir_type == "String"}
    str := all_strings[_]
    
    regex.match("(?i)pwd=;", str.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": str,
        "path": parent.path,
        "description": "Empty password in connection string - Connection strings must not have empty passwords. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_strings := {n | walk(parent, [_, n]); n.ir_type == "String"}
    str := all_strings[_]
    
    regex.match("(?i)://[^:]+:@", str.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": str,
        "path": parent.path,
        "description": "Empty password in connection string - Connection strings must not have empty passwords. (CWE-258)"
    }
}

contains_password_keyword(name) {
    some keyword in password_keywords
    contains(name, keyword)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}