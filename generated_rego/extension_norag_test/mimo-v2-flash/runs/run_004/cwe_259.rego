package glitch

import data.glitch_lib

sensitive_attributes := {"password", "secret", "token", "api_key", "credential", "auth_string", "admin_password", "master_key", "connection_string", "database_url", "keystore_password", "truststore_password", "sha512_password", "private_key", "key", "auth_token", "auth_key"}

connection_string_pattern := `://[^:\s]+:[^@\s]+@`

default_credentials := {"admin", "root", "user", "administrator", "default", "admin123", "password", "123456", "cassandra", "telarista", "some_password", "guacamole_user", "guacamole_db"}

check_sensitive_name(name) = true {
    some kw
    kw = sensitive_attributes[_]
    contains(lower(name), kw)
} else = false

check_string_value(value) = true {
    value.ir_type == "String"
    value.value != ""
} else = false

check_default_credentials(value) = true {
    value.ir_type == "String"
    some cred
    cred = default_credentials[_]
    contains(value.value, cred)
} else = false

check_connection_string(value) = true {
    value.ir_type == "String"
    regex.match(connection_string_pattern, value.value)
} else = false

is_dynamic_reference(value) = true {
    value.ir_type == "VariableReference"
} else = true {
    value.ir_type == "FunctionCall"
} else = true {
    value.ir_type == "MethodCall"
} else = false

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value != ""
    some kw
    kw = sensitive_attributes[_]
    contains(lower(node.value), kw)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password - Avoid using hard-coded passwords. Use secret managers or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    (node.ir_type == "Attribute" or node.ir_type == "Variable")
    check_sensitive_name(node.name)
    check_string_value(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password in attribute/variable - Avoid using hard-coded passwords. Use secret managers or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_node := pair.key
    value_node := pair.value
    key_node.ir_type == "String"
    value_node.ir_type == "String"
    check_sensitive_name(key_node.value)
    check_string_value(value_node)
    result := {
        "type": "sec_hard_pass",
        "element": key_node,
        "path": parent.path,
        "description": "Hard-coded password in hash - Avoid using hard-coded passwords. Use secret managers or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value != ""
    check_connection_string(node)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Embedded credentials in connection string - Avoid embedding credentials in connection strings. Use secret managers or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    (node.ir_type == "Attribute" or node.ir_type == "Variable")
    check_sensitive_name(node.name)
    check_string_value(node.value)
    check_default_credentials(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Default credentials in attribute/variable - Avoid using default or common credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_node := pair.key
    value_node := pair.value
    key_node.ir_type == "String"
    value_node.ir_type == "String"
    check_sensitive_name(key_node.value)
    check_default_credentials(value_node)
    result := {
        "type": "sec_hard_pass",
        "element": key_node,
        "path": parent.path,
        "description": "Default credentials in hash - Avoid using default or common credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value != ""
    some cred
    cred = default_credentials[_]
    contains(node.value, cred)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Default credentials found in string - Avoid using default or common credentials. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    (node.ir_type == "Attribute" or node.ir_type == "Variable")
    check_sensitive_name(node.name)
    check_string_value(node.value)
    not is_dynamic_reference(node.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Missing secret reference - Sensitive fields should use dynamic sourcing from secret managers or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_node := pair.key
    value_node := pair.value
    key_node.ir_type == "String"
    value_node.ir_type == "String"
    check_sensitive_name(key_node.value)
    check_string_value(value_node)
    not is_dynamic_reference(value_node)
    result := {
        "type": "sec_hard_pass",
        "element": key_node,
        "path": parent.path,
        "description": "Missing secret reference - Sensitive fields should use dynamic sourcing from secret managers or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value != ""
    regex.match(`^[A-Za-z0-9+/]*={0,2}$`, node.value)
    strlen(node.value) > 20
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Base64-encoded secret - Avoid storing secrets in base64 encoding. Use proper secret management. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "Array"
    element := node.value[_]
    element.ir_type == "String"
    element.value != ""
    check_connection_string(element)
    result := {
        "type": "sec_hard_pass",
        "element": element,
        "path": parent.path,
        "description": "Embedded credentials in connection string array - Avoid embedding credentials in connection strings. Use secret managers or environment variables. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value != ""
    some kw
    kw = sensitive_attributes[_]
    contains(lower(node.value), kw)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password in string - Avoid using hard-coded passwords. Use secret managers or environment variables. (CWE-259)"
    }
}