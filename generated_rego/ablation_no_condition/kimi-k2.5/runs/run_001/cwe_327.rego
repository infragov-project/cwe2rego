package glitch

import data.glitch_lib

weak_crypto_patterns := {"des", "3des", "tripledes", "md4", "md5", "sha", "sha1", "sha-1", "rc2", "rc4", "blowfish", "tea", "xtea", "rot13", "rot25", "xor", "base64", "md5_crypt", "sha1_crypt", "des_crypt", "cbc", "ecb", "md5crypt", "sha1crypt", "descrypt"}

crypto_attr_patterns := "cipher|crypto|digest|hmac|sign|ssl|tls|checksum|encrypt|hash|auth.*method|protocol"

check_weak_crypto_pattern(value) {
    some p
    weak_crypto_patterns[p]
    regex.match(sprintf("(?i)(^|[^a-z0-9_])%s([^a-z0-9_]|$)", [p]), value)
}

check_crypto_attr_name(name) {
    regex.match(sprintf("(?i).*(%s).*", [crypto_attr_patterns]), name)
}

# Check if string is a file extension pattern, not crypto usage
is_file_extension_pattern(value) {
    regex.match(`\.[a-zA-Z0-9]+\$?$`, value)
    not regex.match(`(?i)(md5|sha|des|rc4|blowfish|tea)`, value)
}

# Check if value is a regex replace pattern (contains | before extension)
is_regex_replace_pattern(value) {
    regex.match(`\|\.[a-zA-Z0-9]+\$`, value)
}

# Safe check for weak crypto that excludes file patterns
safe_check_weak_crypto(value) {
    check_weak_crypto_pattern(value)
    not is_file_extension_pattern(value)
    not is_regex_replace_pattern(value)
}

# Collect all unit blocks recursively from all levels
all_unit_blocks[ub] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.path != ""
}

# Find any string with weak crypto pattern in a node tree
find_weak_crypto_string(node, result) {
    walk(node, [path, n])
    n.ir_type == "String"
    safe_check_weak_crypto(n.value)
    result := n
}

# Detect weak crypto in FunctionCall arguments (catches Ansible filters like hash('sha1'))
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [_, node])
    node.ir_type == "FunctionCall"

    some i
    arg := node.args[i]
    arg.ir_type == "String"
    safe_check_weak_crypto(arg.value)

    result := {
        "type": "sec_weak_crypt",
        "element": arg,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}

# Detect weak crypto in Attribute values with crypto-related names
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [_, node])
    node.ir_type == "Attribute"
    check_crypto_attr_name(node.name)
    find_weak_crypto_string(node.value, n)

    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}

# Detect weak crypto in Variable values with crypto-related names
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [_, node])
    node.ir_type == "Variable"
    check_crypto_attr_name(node.name)
    find_weak_crypto_string(node.value, n)

    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}

# Detect weak crypto in Hash key-value pairs where key suggests crypto usage - handles nested Arrays
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [_, node])
    node.ir_type == "Hash"

    some pair
    node.value[pair]
    pair.key.ir_type == "String"
    check_crypto_attr_name(pair.key.value)
    find_weak_crypto_string(pair.value, n)

    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}

# Detect weak crypto in Array elements - handles vars_prompt structures
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [_, node])
    node.ir_type == "Array"

    some idx
    elem := node.value[idx]
    walk(elem, [_, h])
    h.ir_type == "Hash"

    some pair
    h.value[pair]
    pair.key.ir_type == "String"
    check_crypto_attr_name(pair.key.value)
    find_weak_crypto_string(pair.value, n)

    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}

# Detect direct weak crypto algorithm in FunctionCall name
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [_, node])
    node.ir_type == "FunctionCall"
    check_weak_crypto_pattern(node.name)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}

# Detect weak crypto in Access right-hand side (e.g., hash lookups with crypto names)
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [_, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    safe_check_weak_crypto(node.right.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node.right,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}

# Detect weak crypto in ConditionalStatement statements (handles Chef nested variables)
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [_, node])
    node.ir_type == "ConditionalStatement"

    walk(node, [_, stmt])
    stmt.ir_type == "Variable"
    check_crypto_attr_name(stmt.name)
    find_weak_crypto_string(stmt.value, n)

    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}

# Fallback: detect weak crypto in any string with crypto context in path/name
Glitch_Analysis[result] {
    ub := all_unit_blocks[_]

    walk(ub, [path, node])
    node.ir_type == "String"
    safe_check_weak_crypto(node.value)

    # Check if any parent in path has crypto-related name
    some i
    parent := path[i]
    (
        parent.ir_type == "Attribute"
        check_crypto_attr_name(parent.name)
    ) | (
        parent.ir_type == "Variable"
        check_crypto_attr_name(parent.name)
    ) | (
        parent.ir_type == "Hash"
        some pair
        parent.value[pair]
        pair.key.ir_type == "String"
        check_crypto_attr_name(pair.key.value)
    )

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": ub.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms. (CWE-327)"
    }
}