package glitch

import data.glitch_lib

credential_keywords := {
    "password", "secret", "key", "token", "auth", "credential", "passphrase",
    "api_key", "access_token", "private_key", "client_secret", "secret_key",
    "username", "user", "login", "db_password", "db_username", "db_pass",
    "connection_string", "uri", "url", "dsn"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)[_]
    name_lower := lower(variable.name)
    keyword := credential_keywords[_]
    contains(name_lower, keyword)
    variable.value.ir_type == "String"
    variable.value.value != ""
    not contains(variable.value.value, "{{")
    not contains(variable.value.value, "%{")
    not contains(variable.value.value, "${")
    
    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": sprintf("Hard-coded credentials in variable: %s", [variable.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attribute := glitch_lib.all_attributes(parent)[_]
    name_lower := lower(attribute.name)
    keyword := credential_keywords[_]
    contains(name_lower, keyword)
    attribute.value.ir_type == "String"
    attribute.value.value != ""
    not contains(attribute.value.value, "{{")
    not contains(attribute.value.value, "%{")
    not contains(attribute.value.value, "${")
    
    result := {
        "type": "sec_hard_secr",
        "element": attribute,
        "path": parent.path,
        "description": sprintf("Hard-coded credentials in attribute: %s", [attribute.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Hash"
    pair := n.value[_]
    pair.key.ir_type == "String"
    key_name := pair.key.value
    key_lower := lower(key_name)
    keyword := credential_keywords[_]
    contains(key_lower, keyword)
    pair.value.ir_type == "String"
    pair.value.value != ""
    not contains(pair.value.value, "{{")
    not contains(pair.value.value, "%{")
    not contains(pair.value.value, "${")
    
    result := {
        "type": "sec_hard_secr",
        "element": pair.key,
        "path": parent.path,
        "description": sprintf("Hard-coded credentials in hash key: %s", [key_name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "String"
    n.value != ""
    value_lower := lower(n.value)
    pattern := "(password|pass|pwd|secret|key|token|auth|credential)=['\\\"]?[^'\\\"]+['\\\"]?"
    regex.match(pattern, value_lower)
    
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": sprintf("Hard-coded credentials pattern in string: %s", [n.value])
    }
}