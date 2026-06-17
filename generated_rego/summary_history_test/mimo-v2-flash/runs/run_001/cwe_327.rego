package glitch

import data.glitch_lib

weak_encryption_patterns := {"DES", "3DES", "RC4", "AES[-_]?128", "AES[-_]?ECB", "AES[-_]?GCM[-_]?128", "md5_crypt"}
outdated_protocol_patterns := {"SSLv2", "SSLv3", "TLSv1\\.0", "TLSv1\\.1", "SSHv1"}
insecure_hash_patterns := {"MD5", "SHA[-_]?1", "RSA_WITH_MD5", "ECDSA_WITH_SHA1", "sha1", "password_md5", "SHA"}
weak_key_derivation_patterns := {"PBKDF1", "unsalted"}
implementation_flaw_patterns := {"ECB", "true", "false"}
hardcoded_key_patterns := {"true", "NONE", "CUSTOM"}

extract_strings_recursive(node) = strings {
    strings := {s |
        walk(node, [path, n])
        n.ir_type == "String"
        s := lower(n.value)
    }
}

check_node_value(node, pattern_set, description, parent_path) = result {
    string_values := extract_strings_recursive(node)
    count(string_values) > 0
    pattern := pattern_set[_]
    s := string_values[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), s)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent_path,
        "description": description
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute" or node.ir_type == "Variable" or node.ir_type == "FunctionCall" or node.ir_type == "Hash" or node.ir_type == "String"
    result := check_node_value(node, weak_encryption_patterns, "Use of broken or risky cryptographic algorithm (CWE-327)", parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute" or node.ir_type == "Variable" or node.ir_type == "FunctionCall" or node.ir_type == "Hash" or node.ir_type == "String"
    result := check_node_value(node, outdated_protocol_patterns, "Use of outdated protocol version (CWE-327)", parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute" or node.ir_type == "Variable" or node.ir_type == "FunctionCall" or node.ir_type == "Hash" or node.ir_type == "String"
    result := check_node_value(node, insecure_hash_patterns, "Use of insecure hashing algorithm (CWE-327)", parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "key_length"
    node.value.ir_type == "Integer"
    node.value.value <= 1024
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate key management - weak key length (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute" or node.ir_type == "Variable" or node.ir_type == "FunctionCall" or node.ir_type == "Hash" or node.ir_type == "String"
    result := check_node_value(node, weak_key_derivation_patterns, "Inadequate key management - weak key derivation (CWE-327)", parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute" or node.ir_type == "Variable" or node.ir_type == "FunctionCall" or node.ir_type == "Hash" or node.ir_type == "String"
    result := check_node_value(node, implementation_flaw_patterns, "Implementation flaw in cryptographic configuration (CWE-327)", parent.path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute" or node.ir_type == "Variable" or node.ir_type == "FunctionCall" or node.ir_type == "Hash" or node.ir_type == "String"
    result := check_node_value(node, hardcoded_key_patterns, "Hardcoded cryptographic keys or non-compliant settings (CWE-327)", parent.path)
}