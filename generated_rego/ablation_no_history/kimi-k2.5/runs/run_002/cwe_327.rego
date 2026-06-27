package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "tripledes", "rc2", "rc4", "blowfish", "md4", "md5", "sha", "sha1", "sha-1", "ripemd", "whirlpool", "ssl2", "ssl3", "tls1", "tls1_0", "tls1_1", "tls_1_0", "tls_1_1", "export", "null", "anon", "md5withrsa", "sha1withrsa", "des-cbc", "rc4-md5", "export1024"}

crypto_attr_patterns := {"cipher", "encryption", "algorithm", "hash", "digest", "checksum", "mac", "hmac", "signature", "signing", "password_hash", "kdf", "key_derivation", "key_exchange", "tls", "ssl", "protocol", "ssl_version", "tls_version", "min_tls_version", "max_tls_version", "sse_algorithm", "message_digest"}

weak_functions := {"md5", "sha1", "sha", "des", "rc2", "rc4", "blowfish", "md4"}

# Normalize algorithm name for comparison
normalize_alg(value) = normalized {
    lower_val := lower(value)
    # Remove common separators and standardize
    normalized := regex.replace(lower_val, "[^a-z0-9]", "")
}

# Check if a value matches weak algorithm list
has_weak_algorithm(value) {
    alg := weak_algorithms[_]
    normalize_alg(value) == alg
}

# Check if attribute name suggests cryptographic context
is_crypto_attr(name) {
    lower_name := lower(name)
    pattern := crypto_attr_patterns[_]
    contains(lower_name, pattern)
}

# Check if function name is a weak cryptographic function
is_weak_function(name) {
    lower_name := lower(name)
    weak_funcs := weak_functions[_]
    lower_name == weak_funcs
}

contains(str, substr) {
    lower_str := lower(str)
    lower_substr := lower(substr)
    regex.match(sprintf(".*%s.*", [lower_substr]), lower_str)
}

# Extract string content from various node types that might contain weak algorithms
extract_string_candidates(node, candidates) {
    node.ir_type == "String"
    candidates = [node.value]
}

extract_string_candidates(node, candidates) {
    node.ir_type == "VariableReference"
    candidates = [node.value]
}

extract_string_candidates(node, candidates) {
    node.ir_type == "FunctionCall"
    candidates = array.concat([node.name], [a.value | a := node.args[_]; a.ir_type == "String"])
}

extract_string_candidates(node, candidates) {
    node.ir_type == "MethodCall"
    candidates = [node.method]
}

# For Sum (string concatenation), collect all nested strings
extract_string_candidates(node, candidates) {
    node.ir_type == "Sum"
    candidates := [c | walk(node, [_, n]); n.ir_type == "String"; c := n.value]
}

# Check if any candidate contains weak algorithm in crypto context
has_weak_in_candidates(candidates) {
    candidate := candidates[_]
    has_weak_algorithm(candidate)
}

# Main check for weak crypto in attribute values
check_value_weak_crypto(node) {
    extract_string_candidates(node, candidates)
    has_weak_in_candidates(candidates)
}

# Check for direct weak algorithm match in specific crypto attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes at unit block level
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_crypto_attr(attr.name)
    check_value_weak_crypto(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated cryptographic algorithms should not be used. (CWE-327)"
    }
}

# Check variables with crypto-related names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_crypto_attr(v.name)
    check_value_weak_crypto(v.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated cryptographic algorithms should not be used. (CWE-327)"
    }
}

# Check atomic unit attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_crypto_attr(attr.name)
    check_value_weak_crypto(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated cryptographic algorithms should not be used. (CWE-327)"
    }
}

# Detect weak crypto function calls with crypto-related naming
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.ir_type == "FunctionCall"
    is_weak_function(node.name)
    # Only flag if in crypto context or has weak algorithm as argument
    has_crypto_context(node)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated cryptographic algorithms should not be used. (CWE-327)"
    }
}

# Helper to determine if function call is in crypto context
has_crypto_context(node) {
    # Check if any argument contains weak algorithm reference
    arg := node.args[_]
    arg.ir_type == "String"
    has_weak_algorithm(arg.value)
}

has_crypto_context(node) {
    # Check function name itself suggests crypto context
    fn_lower := lower(node.name)
    contains(fn_lower, "encrypt")
}

has_crypto_context(node) {
    fn_lower := lower(node.name)
    contains(fn_lower, "hash")
}

has_crypto_context(node) {
    fn_lower := lower(node.name)
    contains(fn_lower, "crypto")
}

has_crypto_context(node) {
    fn_lower := lower(node.name)
    contains(fn_lower, "cipher")
}

# Detect weak algorithms in shell/command strings when explicitly flagged
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    
    # Command execution contexts where crypto flags are used
    command_attrs := {"shell", "command", "cmd"}
    unit.type == command_attrs[_]
    
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    
    # Look for command string with crypto algorithm flags
    attr.name == command_attrs[_]
    contains_weak_crypto_in_command(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated cryptographic algorithms should not be used. (CWE-327)"
    }
}

# Check command strings for explicit weak crypto algorithm flags
contains_weak_crypto_in_command(node) {
    # Extract full command string by walking all string components
    walk(node, [_, n])
    n.ir_type == "String"
    
    cmd := n.value
    
    # Look for explicit algorithm specification patterns in commands
    # e.g., "-md md5", "-sha1", "-aes-256-cbc -md md5"
    regex_patterns := [
        "-md\\s+(md4|md5|sha|sha1|sha-1)",
        "-digest\\s+(md4|md5|sha|sha1|sha-1)",
        "-sha1\\b",
        "-md5\\b",
        "\\bmd5\\s+-(in|out|k)",
        "\\bsha1\\s+-(in|out|k)"
    ]
    
    pattern := regex_patterns[_]
    regex.match(pattern, cmd)
}