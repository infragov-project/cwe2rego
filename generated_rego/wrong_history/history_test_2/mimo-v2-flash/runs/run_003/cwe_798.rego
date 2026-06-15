package glitch

import data.glitch_lib

credential_keywords := {"password", "secret", "token", "key", "credential", "passwd", "pwd", "auth", "api_key", "access_key", "secret_key", "private_key", "client_secret"}

contains_credential_keyword(str) {
    lower_str := lower(str)
    some keyword in credential_keywords
    contains(lower_str, lower(keyword))
}

contains_hardcoded_credential(node) {
    node.ir_type == "Hash"
    kv := node.value[_]
    key := kv.key
    value := kv.value
    key.ir_type == "String"
    contains_credential_keyword(key.value)
    value.ir_type == "String"
} else {
    node.ir_type == "Hash"
    kv := node.value[_]
    value := kv.value
    contains_hardcoded_credential(value)
} else {
    node.ir_type == "Array"
    elem := node.value[_]
    contains_hardcoded_credential(elem)
} else {
    false
}

has_hardcoded_credential(var_or_attr) {
    contains_credential_keyword(var_or_attr.name)
    var_or_attr.value.ir_type == "String"
} else {
    contains_hardcoded_credential(var_or_attr.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variable := glitch_lib.all_variables(parent)[_]
    has_hardcoded_credential(variable)
    
    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding sensitive authentication data in code. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attribute := glitch_lib.all_attributes(parent)[_]
    has_hardcoded_credential(attribute)
    
    result := {
        "type": "sec_hard_secr",
        "element": attribute,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding sensitive authentication data in code. (CWE-798)"
    }
}