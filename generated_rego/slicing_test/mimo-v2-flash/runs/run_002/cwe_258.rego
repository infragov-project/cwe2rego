package glitch

import data.glitch_lib

password_keywords := {"password", "pass", "pwd", "passwd", "secret", "token", "key", "api_token", "access_key", "secret_key", "sslclientkey"}

is_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

contains_password_keyword(name) {
    lower_name := lower(name)
    keyword := password_keywords[_]
    contains(lower_name, keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := glitch_lib.all_variables(parent)[_]
    contains_password_keyword(var.name)
    is_empty_password(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration variable. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    contains_password_keyword(attr.name)
    is_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration attribute. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    func_call := {n |
        walk(parent, [_, n])
        n.ir_type == "FunctionCall"
    }[_]
    
    func_call.name == "mysql_password"
    count(func_call.args) > 0
    arg := func_call.args[0]
    
    arg.ir_type == "VariableReference"
    contains_password_keyword(arg.value)
    
    var := glitch_lib.all_variables(parent)[_]
    var.name == arg.value
    is_empty_password(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration variable used in function call. (CWE-258)"
    }
}