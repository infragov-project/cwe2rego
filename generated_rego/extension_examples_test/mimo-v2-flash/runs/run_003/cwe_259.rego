package glitch

import data.glitch_lib
import future.keywords.in

# Helper function to check if a value is a reference (not hard-coded)
is_reference(value) {
    value.ir_type == "VariableReference"
} else {
    value.ir_type == "FunctionCall"
} else {
    value.ir_type == "Access"
} else {
    value.ir_type == "MethodCall"
} else {
    value.ir_type == "String"
    regex.match(`^\$\{.*\}$`, value.value)
} else {
    value.ir_type == "String"
    regex.match(`^{{.*}}$`, value.value)
} else {
    value.ir_type == "String"
    regex.match(`^env\..*`, value.value)
}

# Helper function to check if a field name indicates a password field
is_password_field(name) {
    lower_name := lower(name)
    contains(lower_name, "password")
} else {
    lower_name := lower(name)
    contains(lower_name, "passphrase")
} else {
    lower_name := lower(name)
    contains(lower_name, "secret")
} else {
    lower_name := lower(name)
    contains(lower_name, "credential")
} else {
    lower_name := lower(name)
    contains(lower_name, "key")
} else {
    lower_name := lower(name)
    contains(lower_name, "sha512")
} else {
    lower_name := lower(name)
    contains(lower_name, "mysql_password")
} else {
    lower_name := lower(name)
    contains(lower_name, "mongodb_password")
} else {
    lower_name := lower(name)
    contains(lower_name, "mongo_password")
} else {
    lower_name := lower(name)
    contains(lower_name, "jwt_secret")
} else {
    lower_name := lower(name)
    contains(lower_name, "api_key")
} else {
    lower_name := lower(name)
    contains(lower_name, "auth_token")
}

# Rule 1: Detect hardcoded passwords in direct attributes and variables (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all key-value pairs (variables and attributes)
    all_kv := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    kv := all_kv[_]
    
    # Check if the field name indicates a password field
    is_password_field(kv.name)
    
    # Check if the value is a hardcoded string (not a reference)
    kv.value.ir_type == "String"
    kv.value.value != ""
    not is_reference(kv.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": kv,
        "path": parent.path,
        "description": "Hardcoded password detected in IaC attribute/variable. (CWE-259)"
    }
}

# Rule 2: Detect hardcoded passwords in hash values (nested dictionaries)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    some index
    kv := node.value[index]
    kv.key.ir_type == "String"
    is_password_field(kv.key.value)
    
    # Check if the value is a hardcoded string (not a reference)
    kv.value.ir_type == "String"
    kv.value.value != ""
    not is_reference(kv.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": kv.value,
        "path": parent.path,
        "description": "Hardcoded password in configuration hash. (CWE-259)"
    }
}

# Rule 3: Detect hardcoded passwords in connection strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    
    # Check if it's a connection string with embedded credentials
    regex.match(`(?i)\b\w+://[^:\s]+:[^@\s]+@[^/\s]+`, node.value)
    not is_reference(node)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded password in connection string. (CWE-259)"
    }
}

# Rule 4: Detect default username/password pairs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    # Look for username and password keys in the same hash
    some i, j
    username_kv := node.value[i]
    password_kv := node.value[j]
    username_kv.key.ir_type == "String"
    password_kv.key.ir_type == "String"
    lower(username_kv.key.value) in {"username", "user", "admin_username", "admin_user"}
    is_password_field(password_kv.key.value)
    
    # Both values must be hardcoded strings
    username_kv.value.ir_type == "String"
    password_kv.value.ir_type == "String"
    username_kv.value.value != ""
    password_kv.value.value != ""
    not is_reference(username_kv.value)
    not is_reference(password_kv.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Default username/password pair detected. (CWE-259)"
    }
}

# Rule 5: Detect hardcoded passwords in array elements (e.g., password lists)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    
    # Check if any array element is a hardcoded password string
    some index
    elem := node.value[index]
    elem.ir_type == "String"
    elem.value != ""
    not is_reference(elem)
    
    # Check if the array context suggests passwords (e.g., the array is under a password-related field)
    # This is a heuristic: if the array is in a hash with a password-related key
    # We check the parent path to see if it contains password-related keywords
    parent_path_str := concat(".", path)
    password_keywords := {"password", "passphrase", "secret", "credential", "key"}
    some kw in password_keywords
    contains(parent_path_str, kw)
    
    result := {
        "type": "sec_hard_pass",
        "element": elem,
        "path": parent.path,
        "description": "Hardcoded password in array element. (CWE-259)"
    }
}