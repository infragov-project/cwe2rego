package glitch

import data.glitch_lib

credential_keywords := {
    "password", "secret", "token", "key", "credential", "auth", 
    "credentialPassword", "apiKey", "accessKey", "secretKey", 
    "defaultPassword", "defaultKey", "staticToken", "adminPassword", 
    "initialSecret", "privateKey", "publicKey", "sshKey", 
    "serviceAccountToken", "jwtSecret", "dbPassword", "rootPassword", 
    "passwd", "pwd", "access_token", 
    "api_key", "secret_key", "client_secret", "private_key", 
    "public_key", "ssh_private_key", "ssh_public_key",
    "truststore", "keystore", "truststore_password", "keystore_password", "sha512_password"
}

safe_patterns := {
    "(?i).*\\$\\{.*\\}", 
    "(?i).*\\{\\{.*\\}\\}", 
    "(?i).*vault:", 
    "(?i).*secret\\(", 
    "(?i).*kms:", 
    "(?i).*sm:", 
    "(?i).*arn:aws:secretsmanager", 
    "(?i).*arn:aws:kms",
    "(?i).*@\\{.*\\}",
    "(?i).*env:",
    "(?i).*file:",
    "(?i).*lookup\\(",
    "(?i).*data\\.",
    "(?i).*var\\.",
    "(?i).*module\\.",
    "(?i).*\\$\\{env_.*\\}"
}

contains_credential_keyword(str) {
    keyword := credential_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), str)
}

is_safe_reference(str) {
    pattern := safe_patterns[_]
    regex.match(pattern, str)
}

# Check all string values in the IR for hard-coded credentials
Glitch_Analysis[result] {
    ub := glitch_lib._gather_parent_unit_blocks[_]
    ub.path != ""
    walk(ub, [path, node])
    node.ir_type == "String"
    node.value != ""
    count(path) >= 2
    parent := path[count(path) - 2]
    is_key_value := is_key_value_parent(parent)
    key_name := get_key_name(parent, node, is_key_value)
    contains_credential_keyword(key_name)
    not is_safe_reference(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": ub.path,
        "description": "Use of hard-coded credentials - Credentials should not be embedded in code. (CWE-798)"
    }
}

# Helper function to check if the parent is a key-value pair (KeyValue, Variable, or Attribute)
is_key_value_parent(parent) {
    parent.ir_type == "KeyValue"
} else {
    parent.ir_type == "Variable"
} else {
    parent.ir_type == "Attribute"
}

# Helper function to get the key name from the parent
get_key_name(parent, node, is_key_value) = key_name {
    is_key_value
    key_name := parent.name
} else = key_name {
    parent.ir_type == "Hash"
    pairs := [pair | pair := parent.value[_]; pair.value == node]
    count(pairs) == 1
    key_name := pairs[0].key.value
} else = key_name {
    key_name := ""
}