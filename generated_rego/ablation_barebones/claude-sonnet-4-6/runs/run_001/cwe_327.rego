package glitch

import data.glitch_lib

weak_crypto_pattern := "(?i).*(des|3des|triple.des|md4|md5|sha-?1|rc2|rc4|blowfish|arcfour|sslv2|sslv3|tls1\\.0|tls1\\.1|tlsv1\\.0|tlsv1\\.1).*"

crypto_name_pattern := "(?i).*(cipher|encrypt|algorithm|hash|digest|ssl|tls|kex|hmac|checksum|crypto|signature).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(crypto_name_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_crypto_pattern, attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms such as DES, MD5, SHA1, or RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    regex.match(crypto_name_pattern, v.name)
    v.value.ir_type == "String"
    regex.match(weak_crypto_pattern, v.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms such as DES, MD5, SHA1, or RC4. (CWE-327)"
    }
}