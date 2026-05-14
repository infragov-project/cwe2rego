package glitch

import data.glitch_lib

password_keywords = {"password", "pass", "pwd", "secret", "key", "token", "credential", "auth", "authentication", "login", "api_key", "access_key", "secret_key"}
password_functions = {"mysql_password", "password", "encrypt_password", "hash_password", "md5", "sha", "sha1", "sha256", "bcrypt", "pbkdf2"}

check_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

contains_password_keyword(name) {
    lower_name := lower(name)
    password_keywords[keyword]
    contains(lower_name, keyword)
}

contains_password_function(name) {
    lower_name := lower(name)
    password_functions[func]
    contains(lower_name, func)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variable := parent.variables[_]
    contains_password_keyword(variable.name)
    check_empty_password(variable.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - Avoid setting passwords to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    contains_password_keyword(attr.name)
    check_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in atomic unit attribute - Avoid setting passwords to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "FunctionCall"
    func_call := attr.value
    contains_password_function(func_call.name)
    
    some i
    i < count(func_call.args)
    arg := func_call.args[i]
    
    check_empty_password(arg)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Password function called with empty argument - Avoid using empty passwords in functions. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "FunctionCall"
    func_call := attr.value
    contains_password_function(func_call.name)
    
    some i
    i < count(func_call.args)
    arg := func_call.args[i]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    
    some j
    j < count(parent.variables)
    variable := parent.variables[j]
    variable.name == var_name
    check_empty_password(variable.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Password function called with empty variable reference - Avoid using empty passwords in functions. (CWE-258)"
    }
}