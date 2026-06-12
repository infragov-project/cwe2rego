package glitch

import data.glitch_lib

credential_keywords := {"password", "secret", "key", "token", "credential", "auth", "passwd", "api_key", "access_key", "private_key", "shared_key", "passphrase"}

is_credential_name(name) {
    name_lower := lower(name)
    keyword := credential_keywords[_]
    glitch_lib.contains(name_lower, keyword)
    # Exclude common non-credential patterns
    not regex.match("^(user_objectclass|user_id_attribute|user_name_attribute|user_mail_attribute|user_enabled_attribute|auth_type|auth_url|www_authenticate_uri|user_domain_name)$", name_lower)
}

is_credential_value(value) {
    value.ir_type == "String"
    value.value != ""
    # Exclude obvious non-credential strings
    not regex.match("^(cn=|dc=|uid=|/etc/|/var/|/root/|org\\.|com\\.|net\\.|/|Default|password|http://|ldaps://)", value.value)
    not value.value == "changeme"
    not value.value == "root"
    not value.value == "Administrator"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all Variables and Attributes
    all_kvs := {n | walk(parent, [path, n]); n.ir_type == "Variable"} | {n | walk(parent, [path, n]); n.ir_type == "Attribute"}
    kv := all_kvs[_]
    is_credential_name(kv.name)
    is_credential_value(kv.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Hard-coded credential found in infrastructure resource - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Hash key-value pairs (nested credentials)
    all_hashes := {n | walk(parent, [path, n]); n.ir_type == "Hash"}
    hash := all_hashes[_]
    kv := hash.value[_]
    
    kv.key.ir_type == "String"
    key_name := kv.key.value
    is_credential_name(key_name)
    
    value := kv.value
    is_credential_value(value)
    
    result := {
        "type": "sec_hard_secr",
        "element": kv.key,
        "path": parent.path,
        "description": "Hard-coded credential found in infrastructure resource - Avoid using hard-coded credentials. (CWE-798)"
    }
}