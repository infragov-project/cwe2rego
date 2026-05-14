package glitch

import data.glitch_lib

# Define keywords for secrets and authentication
secret_keywords := {"password", "secret", "token", "passphrase", "key", "credential", "auth", "sha512_password"}

# Check if a string contains a secret keyword (case-insensitive)
contains_secret_keyword(s) {
    lower_s := lower(s)
    contains(lower_s, secret_keywords[_])
}

# Check if an attribute/key name suggests a secret
is_secret_key(key_name) {
    is_string(key_name)
    contains_secret_keyword(key_name)
} else {
    # If key_name is a complex expression, check its string representation
    key_name.ir_type == "String"
    contains_secret_keyword(key_name.value)
}

# Check if a value is a hardcoded secret (String literal)
is_hardcoded_secret(value_node) {
    value_node.ir_type == "String"
    count(value_node.value) > 0
    # Exclude base64-encoded strings or hash strings that might be intended
    not regex.match("^[A-Za-z0-9+/]*={0,2}$", value_node.value)
}

# Check if a value is a variable reference (safe pattern)
is_variable_reference(value_node) {
    value_node.ir_type == "VariableReference"
}

# Check if a value is a function call (potentially safe)
is_function_call(value_node) {
    value_node.ir_type == "FunctionCall"
}

# Rule: Detect hardcoded secrets in nested structures (Hash within Hash, Array within Hash, etc.)
Glitch_Analysis[result] {
    # Get all UnitBlocks with a valid path
    p := glitch_lib._gather_parent_unit_blocks[_]
    p.path != ""

    # Traverse all KeyValues (attributes and variables) in the UnitBlock
    walk(p, [path, n])
    n.ir_type == "KeyValue"

    # Get the key and value nodes
    key_node := n.name
    value_node := n.value

    # Check if the key suggests a secret
    is_secret_key(key_node)

    # Check if the value is a hardcoded secret
    is_hardcoded_secret(value_node)

    # Exclude safe patterns: variable references, function calls
    not is_variable_reference(value_node)
    not is_function_call(value_node)

    # Ensure we are not detecting "no_password: true" or similar safe patterns
    # In the Chef example, "no_password: true" is safe, but "sha512_password: ..." is not
    # This is implicitly handled by is_hardcoded_secret (String check) and key name check

    result := {
        "type": "sec_hard_pass",
        "element": n,
        "path": p.path,
        "description": "Use of Hard-coded Password - Hard-coded passwords in IaC scripts pose a security risk. (CWE-259)"
    }
}