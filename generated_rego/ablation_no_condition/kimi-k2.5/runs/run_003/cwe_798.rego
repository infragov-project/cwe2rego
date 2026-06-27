package glitch

import data.glitch_lib

credential_patterns := {
    "password", "passwd", "pwd", "pass",
    "secret", "secretkey", "secret_key",
    "apikey", "api_key", "apisecret", "api_secret",
    "token", "authtoken", "auth_token",
    "accesskey", "access_key", "access_secret",
    "privatekey", "private_key",
    "sshkey", "ssh_key",
    "credential", "credentials",
    "encryptionkey", "encryption_key",
    "authkey", "auth_key",
    "clientsecret", "client_secret",
    "adminpassword", "admin_password", "rootpassword", "root_password",
    "dbpassword", "db_password", "databasepassword", "database_password",
    "truststorepassword", "truststore_password",
    "keystorepassword", "keystore_password",
    "key_pass", "keypass", "key_password",
    "keystore", "truststore",
    "username", "user_name", "user",
    "login", "key"
}

is_credential_name(name) {
    lower_name := lower(name)
    parts := split(lower_name, ".")
    part := parts[_]
    credential_patterns[part]
} else {
    lower_name := lower(name)
    parts := split(lower_name, "[")
    part := parts[_]
    clean_part := regex.replace(part, "^['\"\\]]*", "")
    clean_part2 := regex.replace(clean_part, "['\"\\]]*$", "")
    credential_patterns[lower(clean_part2)]
} else {
    lower_name := lower(name)
    regex.match("(?:_|-|\\.)password(?:_|-|$)", lower_name)
} else {
    lower_name := lower(name)
    regex.match("(?:_|-|\\.)secret(?:_|-|$)", lower_name)
} else {
    lower_name := lower(name)
    regex.match("(?:_|-|\\.)key(?:_|-|$)", lower_name)
} else {
    credential_patterns[lower(name)]
}

is_hardcoded_value(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not is_placeholder_value(value.value)
}

is_placeholder_value(str) {
    str == ""
} else {
    str == "null"
} else {
    str == "None"
} else {
    regex.match("^\\$\\{.*\\}$", str)
} else {
    regex.match("^\\{\\{.*\\}\\}$", str)
} else {
    regex.match("^(?i)(changeme|change_me|change-it|placeholder|example|sample|test|temp|tmp|temporary|xxxx|####|#####|\\*\\*\\*\\*\\*|-----|your_password|default|none|null|to_be_set|tobe_set|insert_password|put_password_here|my_password|your_key|insert_key|secret_here|\\$::os_service_default)$", str)
}

is_ldap_dn(str) {
    regex.match("^(?i)(uid|cn|dc|ou|o|l|st|c|mail|member|uniqueMember|gidNumber|uidNumber)=", str)
}

is_url(str) {
    regex.match("^(?i)(https?|ftp|ldaps?)://", str)
}

is_java_class(str) {
    regex.match("^[a-z][a-zA-Z0-9_]*(\\.[a-z][a-zA-Z0-9_]*)+$", str)
}

find_hash_entries(node) = entries {
    node.ir_type == "Hash"
    entries := node.value
}

find_hash_entries(node) = entries {
    node.ir_type == "Array"
    entries_array := [entry |
        member := node.value[_]
        member.ir_type == "Hash"
        entry := member.value[_]
    ]
    entries := {e | e := entries_array[_][_]}
}

check_credential_in_entry(entry, parent_path) = result {
    entry.key.ir_type == "String"
    key_str := entry.key.value
    is_credential_name(key_str)
    entry.value.ir_type == "String"
    val_str := entry.value.value
    count(val_str) > 0
    not is_placeholder_value(val_str)
    not is_ldap_dn(val_str)
    not is_url(val_str)
    not is_java_class(val_str)
    result := {
        "type": "sec_hard_secr",
        "element": entry,
        "path": parent_path,
        "description": "Use of Hard-coded Credentials - Avoid hard-coding credentials in IaC scripts. Use secure vaults or environment variables. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.ir_type == "Variable"
    is_credential_name(node.name)
    is_hardcoded_value(node.value)
    not is_ldap_dn(node.value.value)
    not is_url(node.value.value)
    not is_java_class(node.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hard-coding credentials in IaC scripts. Use secure vaults or environment variables. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.ir_type == "Attribute"
    is_credential_name(node.name)
    is_hardcoded_value(node.value)
    not is_ldap_dn(node.value.value)
    not is_url(node.value.value)
    not is_java_class(node.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hard-coding credentials in IaC scripts. Use secure vaults or environment variables. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, container])
    container.ir_type == "Hash"
    walk(container, [_, entry])
    entry.key.ir_type == "String"
    key_str := entry.key.value
    is_credential_name(key_str)
    entry.value.ir_type == "String"
    val_str := entry.value.value
    count(val_str) > 0
    not is_placeholder_value(val_str)
    not is_ldap_dn(val_str)
    not is_url(val_str)
    not is_java_class(val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": entry,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hard-coding credentials in IaC scripts. Use secure vaults or environment variables. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, container])
    container.ir_type == "Array"
    walk(container, [_, member])
    member.ir_type == "Hash"
    walk(member, [_, entry])
    entry.key.ir_type == "String"
    key_str := entry.key.value
    is_credential_name(key_str)
    entry.value.ir_type == "String"
    val_str := entry.value.value
    count(val_str) > 0
    not is_placeholder_value(val_str)
    not is_ldap_dn(val_str)
    not is_url(val_str)
    not is_java_class(val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": entry,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hard-coding credentials in IaC scripts. Use secure vaults or environment variables. (CWE-798)"
    }
}