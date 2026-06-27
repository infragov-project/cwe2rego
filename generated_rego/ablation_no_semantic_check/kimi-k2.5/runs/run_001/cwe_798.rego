package glitch

import data.glitch_lib

# Credential-related field name patterns
credential_field_patterns := {
    "username", "user", "login", "account", "principal", "identity", "admin_user",
    "password", "passwd", "pwd", "secret", "secret_key", "pass", "credentials",
    "token", "auth_token", "access_token", "api_key", "api_secret", "private_key", "ssh_key",
    "connection_string", "db_password", "database_url", "jdbc_url", "mongo_uri",
    "host", "endpoint", "server", "broker", "registry",
    "encryption_key", "decryption_key", "signing_key", "symmetric_key", "master_key", "kek",
    "cert", "certificate", "ca_cert", "tls_cert", "ssl_key"
}

# Common default/weak credential values
weak_credential_values := {
    "admin", "root", "password", "123456", "default", "changeme", "test", "demo", "guest",
    "", "null", "nil", "none"
}

# High entropy patterns (hex, base64-like, key-like strings)
high_entropy_pattern := "^[A-Za-z0-9+/=]{32,}$|^[0-9a-fA-F]{32,}$|BEGIN.*KEY|END.*KEY"

# Check if field name matches credential patterns
is_credential_field(name) {
    lower_name := lower(name)
    pattern := credential_field_patterns[_]
    lower_name == pattern
} else {
    lower_name := lower(name)
    pattern := credential_field_patterns[_]
    contains(lower_name, pattern)
}

# Check if value is a hardcoded string (not a variable reference or function call)
is_hardcoded_value(value) {
    value.ir_type == "String"
    not is_variable_or_function_reference(value)
}

is_hardcoded_value(value) {
    value.ir_type == "Integer"
}

is_hardcoded_value(value) {
    value.ir_type == "Boolean"
}

# Check if value contains weak/default credential
has_weak_credential(value) {
    value.ir_type == "String"
    weak_val := weak_credential_values[_]
    lower(value.value) == weak_val
}

# Check if value has high entropy (potential key material)
has_high_entropy(value) {
    value.ir_type == "String"
    regex.match(high_entropy_pattern, value.value)
}

# Check if value is a variable reference or function call (dynamic)
is_variable_or_function_reference(value) {
    value.ir_type == "VariableReference"
}

is_variable_or_function_reference(value) {
    value.ir_type == "FunctionCall"
}

is_variable_or_function_reference(value) {
    value.ir_type == "MethodCall"
}

# Check Hash values one level deep for hardcoded credentials
check_hash_for_credentials(hash) {
    hash.ir_type == "Hash"
    kv := hash.value[_]
    kv[0].ir_type == "String"
    key_name := kv[0].value
    is_credential_field(key_name)
    is_hardcoded_value(kv[1])
}

# Check Array values one level deep
check_array_for_credentials(arr) {
    arr.ir_type == "Array"
    elem := arr.value[_]
    is_hardcoded_value(elem)
    is_credential_field(elem.value)
}

check_array_for_credentials(arr) {
    arr.ir_type == "Array"
    elem := arr.value[_]
    elem.ir_type == "Hash"
    check_hash_for_credentials(elem)
}

# Main detection for attributes
detect_hardcoded_credential(attr) {
    attr.name == "name"
    is_credential_field(attr.value.value)
    is_hardcoded_value(attr.value)
}

detect_hardcoded_credential(attr) {
    is_credential_field(attr.name)
    is_hardcoded_value(attr.value)
}

detect_hardcoded_credential(attr) {
    is_credential_field(attr.name)
    attr.value.ir_type == "Hash"
    check_hash_for_credentials(attr.value)
}

detect_hardcoded_credential(attr) {
    is_credential_field(attr.name)
    attr.value.ir_type == "Array"
    check_array_for_credentials(attr.value)
}

# Check variables for hardcoded credentials
detect_hardcoded_credential_var(var) {
    is_credential_field(var.name)
    is_hardcoded_value(var.value)
}

detect_hardcoded_credential_var(var) {
    is_credential_field(var.name)
    var.value.ir_type == "Hash"
    check_hash_for_credentials(var.value)
}

detect_hardcoded_credential_var(var) {
    is_credential_field(var.name)
    var.value.ir_type == "Array"
    check_array_for_credentials(var.value)
}

# Check for weak credentials or high entropy in values
detect_suspicious_credential_value(attr) {
    is_credential_field(attr.name)
    has_weak_credential(attr.value)
}

detect_suspicious_credential_value(attr) {
    is_credential_field(attr.name)
    has_high_entropy(attr.value)
}

detect_suspicious_credential_value_var(var) {
    is_credential_field(var.name)
    has_weak_credential(var.value)
}

detect_suspicious_credential_value_var(var) {
    is_credential_field(var.name)
    has_high_entropy(var.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    detect_hardcoded_credential(attr)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded in configuration files. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    detect_suspicious_credential_value(attr)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded in configuration files. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    detect_hardcoded_credential_var(var)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded in configuration files. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    detect_suspicious_credential_value_var(var)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded in configuration files. Use secret management solutions instead. (CWE-798)"
    }
}