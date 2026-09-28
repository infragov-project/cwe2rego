package glitch

import data.glitch_lib

weak_algo_pattern := "(?i)(md5|sha-1|sha1|hmac-md5|hmac-sha1|rsa-md5|rsa-sha1|_sha([^0-9]|$))"

algo_name_pattern := "(?i).*(algorithm|hash_algorithm|digest_algorithm|signing_algorithm|encryption_algorithm|kms_key_algorithm|ssl_policy|cipher_suite|integrity_algorithm|checksum_algorithm|mac_algorithm|key_algorithm|message_digest|hashing_method|crypto_algorithm|auth_algorithm|auth_method|digest|cipher|hash_function|integrity|encrypt).*"

is_weak_algo_string(str) {
    regex.match(weak_algo_pattern, str)
}

is_algo_name(name) {
    regex.match(algo_name_pattern, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_algo_name(node.name)
    node.value.ir_type == "String"
    is_weak_algo_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptography algorithm - MD5 and SHA-1 are considered cryptographically broken and should not be used. Use SHA-256 or stronger. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_algo_name(node.name)
    node.value.ir_type == "String"
    is_weak_algo_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptography algorithm - MD5 and SHA-1 are considered cryptographically broken and should not be used. Use SHA-256 or stronger. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    is_weak_algo_string(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptography algorithm - MD5 and SHA-1 are considered cryptographically broken and should not be used. Use SHA-256 or stronger. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    arg.ir_type == "String"
    is_weak_algo_string(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptography algorithm - MD5 and SHA-1 are considered cryptographically broken and should not be used. Use SHA-256 or stronger. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_algo_name(entry.key.value)
    entry.value.ir_type == "String"
    is_weak_algo_string(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of weak cryptography algorithm - MD5 and SHA-1 are considered cryptographically broken and should not be used. Use SHA-256 or stronger. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    is_weak_algo_string(node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptography algorithm - MD5 and SHA-1 are considered cryptographically broken and should not be used. Use SHA-256 or stronger. (CWE-327)"
    }
}