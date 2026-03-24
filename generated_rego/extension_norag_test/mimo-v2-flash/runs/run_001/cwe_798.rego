package glitch

import data.glitch_lib

credential_keywords = {
    "password", "passphrase", "admin_password", "root_password", "user_password", "secret_password",
    "api_key", "access_key", "secret_key", "key", "token", "auth_token", "secret", "secret_value", "credential",
    "private_key", "ssh_key", "encryption_key", "certificate", "user"
}

is_credential_name(name) {
    name_lower := lower(name)
    keyword := credential_keywords[_]
    contains(name_lower, keyword)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    not glitch_lib.has_variable_reference(value)
}

is_path(value) {
    value.ir_type == "String"
    regex.match(".*[/\\\\].*", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variable := glitch_lib.all_variables(parent)[_]
    is_credential_name(variable.name)
    is_hardcoded_string(variable.value)
    not is_path(variable.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded credential in variable. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attribute := glitch_lib.all_attributes(parent)[_]
    is_credential_name(attribute.name)
    is_hardcoded_string(attribute.value)
    not is_path(attribute.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attribute,
        "path": parent.path,
        "description": "Use of hard-coded credential in attribute. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.key.ir_type == "String"
    is_credential_name(node.key.value)
    node.value.ir_type == "String"
    not glitch_lib.has_variable_reference(node.value)
    not is_path(node.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credential in configuration. (CWE-798)"
    }
}