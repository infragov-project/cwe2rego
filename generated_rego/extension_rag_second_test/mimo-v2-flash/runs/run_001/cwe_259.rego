package glitch

import data.glitch_lib

# Password-related keywords to detect hardcoded secrets
password_keywords := {"password", "secret", "auth_key", "credential", "token", "pwd", "pass", "admin_password", "db_password", "root_password", "api_key", "shared_secret", "default_password", "initial_password", "sha512_password", "keystore_password", "truststore_password", "key"}

# Embedded configuration keywords that might contain passwords
embedded_keywords := {"config_file", "user_data", "startup_script", "custom_data", "inline_script", "connection_string", "app_config", "properties_file", "env", "environment"}

# Default credential usernames
default_usernames := {"admin", "root", "default", "guest"}

# Weak or default passwords
weak_passwords := {"password", "123456", "admin", "qwerty", "letmein"}

# Pattern to match password assignments in strings
password_pattern := "(?i)(password|pwd|pass)\\s*="

# Rule 1: Detect hard-coded passwords in direct attributes (e.g., password: "secret")
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    key_lower := lower(node.name)
    password_keywords_lower := {lower(k) | k := password_keywords[_]}
    password_keywords_lower[key_lower]
    node.value.ir_type == "String"
    node.value.value != ""
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password in resource property - Avoid using hard-coded passwords. (CWE-259)"
    }
}

# Rule 2: Detect passwords in embedded configurations (e.g., in user_data or env variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    key_lower := lower(node.name)
    embedded_keywords_lower := {lower(k) | k := embedded_keywords[_]}
    embedded_keywords_lower[key_lower]
    node.value.ir_type == "String"
    regex.match(password_pattern, node.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password in embedded configuration - Avoid using hard-coded passwords. (CWE-259)"
    }
}

# Rule 3: Detect default credentials with weak passwords
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    key_lower := lower(node.name)
    default_usernames_lower := {lower(u) | u := default_usernames[_]}
    default_usernames_lower[key_lower]
    node.value.ir_type == "String"
    lower_value := lower(node.value.value)
    weak_passwords_lower := {lower(p) | p := weak_passwords[_]}
    weak_passwords_lower[lower_value]
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Default credentials with weak password - Avoid using default or weak passwords. (CWE-259)"
    }
}

# Rule 4: Detect passwords in environment variables or plaintext settings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    key_lower := lower(node.name)
    env_keywords := {"environment_variables", "plaintext", "unencrypted", "env"}
    env_keywords_lower := {lower(k) | k := env_keywords[_]}
    env_keywords_lower[key_lower]
    node.value.ir_type == "String"
    regex.match(password_pattern, node.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password in environment variable - Avoid using hard-coded passwords. (CWE-259)"
    }
}

# Rule 5: Detect passwords in nested hash values (for complex structures like Ansible variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    kv.key.ir_type == "String"
    key_lower := lower(kv.key.value)
    password_keywords_lower := {lower(k) | k := password_keywords[_]}
    password_keywords_lower[key_lower]
    kv.value.ir_type == "String"
    kv.value.value != ""
    result := {
        "type": "sec_hard_pass",
        "element": kv.value,
        "path": parent.path,
        "description": "Hard-coded password in hash key-value pair - Avoid using hard-coded passwords. (CWE-259)"
    }
}

# Rule 6: Detect passwords in variable names (for Chef-like variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    # Extract the last segment of the variable name (after dots or brackets)
    name_parts := split(node.name, ".")
    last_part := name_parts[count(name_parts) - 1]
    # Also check for bracket notation like ['password']
    bracket_pattern := "\\['([^']+)'\\]"
    bracket_matches := regex.find_all_string_submatch(bracket_pattern, node.name)
    last_bracket := count(bracket_matches) > 0 ? bracket_matches[count(bracket_matches) - 1][1] : ""
    key_lower := lower(last_part)
    password_keywords_lower := {lower(k) | k := password_keywords[_]}
    password_keywords_lower[key_lower]
    node.value.ir_type == "String"
    node.value.value != ""
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded password in variable - Avoid using hard-coded passwords. (CWE-259)"
    }
}