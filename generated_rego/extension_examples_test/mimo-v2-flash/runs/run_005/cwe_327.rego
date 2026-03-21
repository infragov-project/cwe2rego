package glitch

import future.keywords.in
import data.glitch_lib

weak_cryptographic_algorithms := {"des", "3des", "triple_des", "rc4", "rsa_1024", "dsa_1024"}
weak_hashing_algorithms := {"md2", "md4", "md5", "sha1", "sha-1"}
weak_cipher_modes := {"ecb", "cbc"}
weak_protocols := {"ssl_v2", "ssl_v3", "tls_1.0", "tls_1.1", "http", "ftp", "telnet", "smtp"}
weak_key_sizes := {512, 64, 80, 1024}

algorithm_keywords := {"algorithm", "cipher", "protocol", "encryption_algorithm", "hash_algorithm", "hash", "password", "key", "salt", "md5", "sha1", "sha", "des", "3des", "rc4", "ssl", "tls"}
mode_keywords := {"mode", "block_cipher_mode"}
protocol_keywords := {"protocol", "tls_version", "ssl_version"}
key_strength_keywords := {"key_length", "key_size", "bits"}
hashing_keywords := {"hashing", "digest", "checksum", "hash_algorithm", "password_hash", "password"}

# Helper to check if a string contains any keyword from a set
contains_keyword(str, keywords) {
    some keyword in keywords
    regex.match(sprintf("(?i).*%s.*", [keyword]), str)
}

# Helper to check if a node contains a weak algorithm using string matching
contains_weak_algorithm_str(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match("(?i).*(des|3des|triple_des|rc4|md2|md4|md5|sha1|sha-1|ecb|cbc|rsa_1024|dsa_1024)", n.value)
}

# Helper to check if a node contains a weak key size
contains_weak_key_size(node) {
    walk(node, [_, n])
    n.ir_type == "Integer"
    n.value in weak_key_sizes
} else {
    walk(node, [_, n])
    n.ir_type == "String"
    to_number(n.value, num)
    num in weak_key_sizes
}

# Helper to check if a node contains a weak protocol
contains_weak_protocol_str(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match("(?i).*(ssl_v2|ssl_v3|tls_1\\.0|tls_1\\.1|http|ftp|telnet|smtp)", n.value)
}

# Helper to check if a node contains a weak hashing algorithm
contains_weak_hashing_str(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    regex.match("(?i).*(md2|md4|md5|sha1|sha-1)", n.value)
}

# Rule 1: Detect weak cryptographic algorithms in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_keyword(attr.name, algorithm_keywords)
    contains_weak_algorithm_str(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

# Rule 2: Detect weak cryptographic algorithms in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_keyword(var.name, algorithm_keywords)
    contains_weak_algorithm_str(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

# Rule 3: Detect weak cipher modes in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_keyword(attr.name, mode_keywords)
    contains_weak_algorithm_str(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cipher mode (CWE-327)"
    }
}

# Rule 4: Detect weak cipher modes in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_keyword(var.name, mode_keywords)
    contains_weak_algorithm_str(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of weak cipher mode (CWE-327)"
    }
}

# Rule 5: Detect insufficient key strength in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_keyword(attr.name, key_strength_keywords)
    contains_weak_key_size(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key strength (CWE-327)"
    }
}

# Rule 6: Detect insufficient key strength in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_keyword(var.name, key_strength_keywords)
    contains_weak_key_size(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Insufficient key strength (CWE-327)"
    }
}

# Rule 7: Detect deprecated hashing in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_keyword(attr.name, hashing_keywords)
    contains_weak_hashing_str(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of deprecated hashing algorithm (CWE-327)"
    }
}

# Rule 8: Detect deprecated hashing in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_keyword(var.name, hashing_keywords)
    contains_weak_hashing_str(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of deprecated hashing algorithm (CWE-327)"
    }
}

# Rule 9: Detect unsecured transport protocols in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_keyword(attr.name, protocol_keywords)
    contains_weak_protocol_str(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of unsecured transport protocol (CWE-327)"
    }
}

# Rule 10: Detect unsecured transport protocols in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_keyword(var.name, protocol_keywords)
    contains_weak_protocol_str(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of unsecured transport protocol (CWE-327)"
    }
}