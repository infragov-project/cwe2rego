package glitch

import data.glitch_lib

# Define a set of keywords that indicate a credential or secret
# This set is based on CWE-798 descriptions (passwords, keys, tokens, etc.)
credential_keywords := {
    "password", "secret", "passwd", "hash", "initial_password", "admin_password",
    "username", "master_username", "user_password", "key", "token", "api_key",
    "authentication_key", "secret_key", "pre_shared_key", "api_token", "ssh_key",
    "secret_string", "secret_value", "connection_string", "truststore_password"
}

# Helper to check if a value is a hardcoded string (not a variable or reference)
is_hardcoded_string(val) {
    val.ir_type == "String"
}

# Helper to identify if a key name suggests a credential
# It uses regex to match keywords anywhere in the key name (case-insensitive)
is_credential_key(key_name) {
    kw := credential_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), key_name)
}

# Helper to check if a string value looks like a hardcoded secret
# We exclude common non-secret strings to reduce false positives (e.g., "Default", "person", "uid")
is_hardcoded_secret(val) {
    is_hardcoded_string(val)
    not regex.match("^(Default|person|uid|mail|cn|member|description|nsAccountLock)$", val.value)
    not regex.match("^/", val.value)
    not regex.match("^[A-Z]:", val.value)
}

# Rule 1: Detect credentials in Variables (e.g., Chef attributes, Ansible vars)
# This covers the Chef example at line 100
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find all variables within the parent block
    walk(parent, [path, var_node])
    var_node.ir_type == "Variable"

    # Check if the variable name indicates a credential
    is_credential_key(var_node.name)

    # Check if the value is a hardcoded secret
    is_hardcoded_secret(var_node.value)

    result := {
        "type": "sec_hard_secr",
        "element": var_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid embedding credentials directly in code. (CWE-798)"
    }
}

# Rule 2: Detect credentials in Attributes (e.g., Ansible tasks, Puppet resources)
# This covers the Ansible example at lines 11-18 and 31, and Puppet example at line 192
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Find all attributes within the parent block
    walk(parent, [path, attr])
    attr.ir_type == "Attribute"

    # Check if the attribute name indicates a credential
    is_credential_key(attr.name)

    # Check if the value is a hardcoded secret
    is_hardcoded_secret(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid embedding credentials directly in code. (CWE-798)"
    }
}

# Rule 3: Detect credentials in deeply nested Hash structures (Ansible vars)
# This specifically targets the nested "password" key in the Ansible example
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Find Hash nodes
    walk(parent, [p, n])
    n.ir_type == "Hash"

    # Iterate over key-value pairs in the hash
    pair := n.value[_]
    key := pair.key
    val := pair.value

    # Check if the key name indicates a credential
    is_credential_key(key.value)

    # Check if the value is a hardcoded secret
    is_hardcoded_secret(val)

    result := {
        "type": "sec_hard_secr",
        "element": key,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid embedding credentials directly in code. (CWE-798)"
    }
}