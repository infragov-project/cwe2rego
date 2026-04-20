package glitch

import data.glitch_lib

import future.keywords.in

password_keywords = {"password", "secret", "pwd", "admin_password", "db_password", "api_key", "token"}
connection_string_keywords = {"connection_string", "uri", "endpoint", "dsn", "jdbc_url"}
default_credentials_keywords = {"default_admin", "default_user", "default_password", "initial_password"}
environment_keywords = {"env", "environment_variable", "export"}
api_key_keywords = {"api_key", "access_token", "secret_key", "credential"}
secret_reference_keywords = {"value", "literal", "plaintext"}

well_known_credentials = {"admin", "root", "password", "123456", "admin123", "letmein", "welcome", "login", "pass", "passwd", "default"}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
}

contains_hardcoded_string(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    n.value != ""
}

contains_hardcoded_password(node, keywords) {
    node.ir_type == "Hash"
    some kv in node.value
    kv.key.ir_type == "String"
    lower(kv.key.value) in keywords
    is_hardcoded_string(kv.value)
}

contains_hardcoded_password(node, keywords) {
    node.ir_type == "Hash"
    some kv in node.value
    kv.key.ir_type == "String"
    lower(kv.key.value) in keywords
    contains_hardcoded_password(kv.value, keywords)
}

contains_hardcoded_password(node, keywords) {
    node.ir_type == "Array"
    some item in node.value
    contains_hardcoded_password(item, keywords)
}

contains_hardcoded_password(node, keywords) {
    node.ir_type == "String"
    is_hardcoded_string(node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    name_lower := lower(node.name)
    password_keywords[name_lower]
    
    contains_hardcoded_password(node.value, password_keywords)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Static Password Assignment - Direct assignment of plaintext password or secret in resource definition. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    name_lower := lower(node.name)
    connection_string_keywords[name_lower]
    
    node.value.ir_type == "String"
    value := node.value.value
    value != ""
    regex.match(`.*[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@.*`, value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded Credentials in Connection Strings - Plaintext credentials embedded in connection strings. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    name_lower := lower(node.name)
    default_credentials_keywords[name_lower]
    
    node.value.ir_type == "String"
    value := node.value.value
    value != ""
    well_known_credentials[value]
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Default Credentials in Configurations - Use of well-known default credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    name_lower := lower(node.name)
    environment_keywords[name_lower]
    
    contains_hardcoded_password(node.value, password_keywords)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Embedded Secrets in Environment Variables - Secrets assigned directly to environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    name_lower := lower(node.name)
    api_key_keywords[name_lower]
    
    contains_hardcoded_password(node.value, api_key_keywords)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded API Keys/Tokens - Static values for authentication tokens or keys. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    name_lower := lower(node.name)
    secret_reference_keywords[name_lower]
    
    is_hardcoded_string(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Insecure Secret References - Use of static values where secrets should be referenced from secure stores. (CWE-259)"
    }
}