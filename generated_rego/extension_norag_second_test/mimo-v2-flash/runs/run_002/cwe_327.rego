package glitch

import data.glitch_lib
import future.keywords.in

weak_patterns := {"(?i)DES", "(?i)3DES", "(?i)RC[2-5]", "(?i)AES[-_]128", "(?i)AES/ECB", "(?i)identity", "(?i)MD[2-4]", "(?i)MD5", "(?i)SHA[-_1]", "(?i)HMAC-MD5", "(?i)HMAC-SHA1", "(?i)SSLv3", "(?i)TLSv1\\.0", "(?i)TLSv1\\.1", "(?i)DSA", "(?i)DH", "(?i)SYMMETRIC_DEFAULT", "(?i)Base64", "(?i)XOR", "(?i)ROT13", "(?i)SSHv1", "(?i)FTP", "(?i)Telnet", "(?i)HTTP"}

crypto_keywords := {"algorithm", "encryption", "hash", "ssl", "tls", "key", "cipher", "protocol", "encoding", "digest", "password", "authentication", "cookie", "stickiness"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    some keyword in crypto_keywords
    contains(attr.name, keyword)
    pattern := weak_patterns[_]
    regex.match(pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "key_length"
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure key management - Key length is too short. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    some path_element in path
    is_string(path_element)
    some keyword in crypto_keywords
    contains(path_element, keyword)
    pattern := weak_patterns[_]
    regex.match(pattern, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm in complex value - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}