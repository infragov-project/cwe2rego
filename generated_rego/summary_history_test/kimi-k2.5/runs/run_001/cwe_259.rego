package glitch

import data.glitch_lib

credential_keywords := {"password", "passwd", "pwd", "secret", "apikey", "api_key", "access_key", "secret_key", "token", "auth_token", "bearer_token", "credential", "credentials", "passphrase", "admin_password", "root_password", "default_password", "initial_password", "key", "sha512_password", "sha256_password", "hashed_password"}

weak_passwords := {"password", "admin", "root", "123456", "P@ssw0rd", "changeme", "changeit", "pass123", "password123", "admin123", "test", "testing", "demo", "example", "secret", "secret123", "12345678", "qwerty", "letmein", "passw0rd", "telarista"}

has_credential_keyword(name) {
    lower_name := lower(name)
    keyword := credential_keywords[_]
    contains(lower_name, keyword)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not glitch_lib.traverse_var(value)
}

is_weak_password(value) {
    value.ir_type == "String"
    lower_val := lower(value.value)
    weak_passwords[lower_val]
}

looks_like_encoded_secret(value) {
    value.ir_type == "String"
    regex.match("^[A-Za-z0-9+/=]{8,}$", value.value)
}

looks_like_hash(value) {
    value.ir_type == "String"
    regex.match("^\\$[0-9a-zA-Z]+\\$[./a-zA-Z0-9]+$", value.value)
}

is_suspicious_credential_value(value) {
    is_weak_password(value)
} else {
    looks_like_encoded_secret(value)
} else {
    looks_like_hash(value)
}

find_credential_entries(node) = results {
    results = {r |
        walk(node, [_, child])
        child.ir_type == "KeyValue"
        child.key.ir_type == "String"
        child.value.ir_type == "String"
        has_credential_keyword(child.key.value)
        is_hardcoded_string(child.value)
        is_suspicious_credential_value(child.value)
        r = {"key": child.key, "value": child.value}
    }
    count(results) > 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    result = detect_credential_at_node(node, parent)
}

detect_credential_at_node(node, parent) = result {
    node.ir_type == "KeyValue"
    node.key.ir_type == "String"
    has_credential_keyword(node.key.value)
    node.value.ir_type == "String"
    is_hardcoded_string(node.value)
    is_suspicious_credential_value(node.value)
    result = {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259) - Key: %s", [node.key.value])
    }
} else = result {
    node.ir_type == "Hash"
    creds := find_credential_entries(node)
    cred := creds[_]
    result = {
        "type": "sec_hard_pass",
        "element": cred.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259) - Key: %s", [cred.key.value])
    }
} else = result {
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "Hash"
    creds := find_credential_entries(elem)
    cred := creds[_]
    result = {
        "type": "sec_hard_pass",
        "element": cred.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259) - Key: %s", [cred.key.value])
    }
} else = result {
    node.ir_type == "Variable"
    has_credential_keyword(node.name)
    node.value.ir_type == "String"
    is_hardcoded_string(node.value)
    is_suspicious_credential_value(node.value)
    result = {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259) - Key: %s", [node.name])
    }
} else = result {
    node.ir_type == "Attribute"
    has_credential_keyword(node.name)
    node.value.ir_type == "String"
    is_hardcoded_string(node.value)
    is_suspicious_credential_value(node.value)
    result = {
        "type": "sec_hard_pass",
        "element": node.value,
        "path": parent.path,
        "description": sprintf("Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259) - Key: %s", [node.name])
    }
}