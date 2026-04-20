package glitch

import data.glitch_lib

encryption_keywords := {"algorithm", "cipher", "encrypt", "ssl", "tls", "hash", "encryption", "key", "auth", "protocol", "store_type", "cipher_suites", "password", "secret", "token", "user", "username", "secret_key", "access_key", "private_key", "public_key", "signature", "md5", "sha", "crypt", "auth_key", "api_key", "client_secret", "client_key", "key_id", "secret_id", "vault", "credential", "cert", "certificate", "ca", "authority", "identity", "authz", "authorization", "authn", "authentication", "bearer", "jwt", "oauth", "sso", "ldap", "active_directory", "server_encryption_options", "client_encryption_options", "enable_advanced", "require_client_auth", "truststore", "truststore_password", "keystore", "keystore_password", "internode_encryption", "md5_crypt", "sha1", "aes", "des", "3des", "rc4", "rsa", "https", "disabled", "none", "default", "local_file", "rotation_period", "key_source", "encryption_enabled", "server_side_encryption", "client_side_encryption", "encryption_scope", "kms_key_id", "storage_encryption", "data_protection", "tls_mode", "authentication_protocol", "compliance_standard", "security_policy", "encryption_level", "fips", "nist", "hipaa", "pci", "gdpr", "aes-128", "aes-256", "sha-1", "rsa-1024", "sslv2", "sslv3", "tls1.0", "tls1.1", "tls1.2", "tls1.3"}

secret_keywords := {"password", "secret", "key", "token", "credential", "private_key", "public_key", "shared_key", "secret_string", "secret_binary", "secret_version", "secret_rotation", "kms_key", "cmk", "customer_managed_key", "hsm", "hardware_security_module", "key_vault", "secret_manager", "secrets_manager", "ssm", "systems_manager", "param_store", "parameter_store"}

weak_pattern := "(?i)\\b(aes-?128|des|3des|rc4|rsa-?1024|md5|sha-?1|sslv2|sslv3|tls1?\\.?0|tls1?\\.?1)\\b"

weak_values := {"disabled", "false", "http", "default", "none"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    encryption_keywords[k]
    contains(lower(a.name), k)
    glitch_lib.traverse(a.value, weak_pattern)
    
    result := {
        "type": "sec_weak_crypt",
        "element": a,
        "path": parent.path,
        "description": "Weak encryption algorithm or protocol detected"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    encryption_keywords[k]
    contains(lower(a.name), k)
    walk(a.value, [path, n])
    (n.ir_type == "Boolean" and n.value == false) or
    (n.ir_type == "String" and lower(n.value) in weak_values)
    
    result := {
        "type": "sec_weak_crypt",
        "element": a,
        "path": parent.path,
        "description": "Encryption explicitly disabled or weak setting detected"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    secret_keywords[k]
    contains(lower(a.name), k)
    walk(a.value, [path, n])
    n.ir_type == "String"
    n.value != ""
    
    result := {
        "type": "sec_weak_crypt",
        "element": a,
        "path": parent.path,
        "description": "Hardcoded secret detected"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    encryption_keywords[k]
    contains(lower(v.name), k)
    glitch_lib.traverse(v.value, weak_pattern)
    
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Weak encryption algorithm or protocol detected"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    encryption_keywords[k]
    contains(lower(v.name), k)
    walk(v.value, [path, n])
    (n.ir_type == "Boolean" and n.value == false) or
    (n.ir_type == "String" and lower(n.value) in weak_values)
    
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Encryption explicitly disabled or weak setting detected"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    secret_keywords[k]
    contains(lower(v.name), k)
    walk(v.value, [path, n])
    n.ir_type == "String"
    n.value != ""
    
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Hardcoded secret detected"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    a.name == "key_source"
    a.value.ir_type == "String"
    contains(lower(a.value.value), "local_file")
    
    result := {
        "type": "sec_weak_crypt",
        "element": a,
        "path": parent.path,
        "description": "Insecure key source detected (local file storage)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    a.name == "rotation_period"
    a.value.ir_type == "String"
    contains(lower(a.value.value), "365")
    
    result := {
        "type": "sec_weak_crypt",
        "element": a,
        "path": parent.path,
        "description": "Weak key rotation period detected (365 days)"
    }
}