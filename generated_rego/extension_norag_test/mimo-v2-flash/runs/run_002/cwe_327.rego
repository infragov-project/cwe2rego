package glitch

import data.glitch_lib

weak_algorithm_pattern := "(?i)\\b(DES|3DES|TripleDES|RC4|MD2|MD4|MD5|SHA1|SHA-1|Blowfish|AES-128|ECB|SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLS 1\\.0|TLS 1\\.1|FTP|SMTP|md5_crypt|password_md5|TLS_RSA_WITH_AES_128_CBC_SHA|TLS_RSA_WITH_AES_256_CBC_SHA)\\b"

non_security_attributes := {"mode", "path", "description", "name", "shell", "become", "become_user", "ignore_errors", "when", "register", "args", "with_items", "with_fileglob"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    not non_security_attributes contains attr.name
    
    glitch_lib.traverse(attr.value, weak_algorithm_pattern)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    v := variables[_]
    
    glitch_lib.traverse(v.value, weak_algorithm_pattern)
    
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}