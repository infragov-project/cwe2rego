package glitch

import data.glitch_lib

credential_suffixes := {"_password", "_passwd", "_secret", "_token", "_key", "_api_key", "_apikey", "_access_key", "_secret_key", "_private_key", "_credentials"}

credential_keywords := {"password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "secret_key", "private_key", "credentials"}

sensitive_prefixes := {"sha512_", "sha256_", "md5_", "bcrypt_", "scrypt_", "pbkdf2_"}

auth_context_keywords := {"auth", "cvauth", "login", "credential", "rsa", "dsa", "ecdsa", "ed25519", "keystore", "truststore", "authentication", "method", "cert"}

is_likely_secret_value(val) {
    count(val) > 0
    not regex.match("^\\s*$", val)
    not regex.match("^\\{\\{", val)
    not regex.match("\\$\\{", val)
    not regex.match("^<%", val)
    not regex.match("^__", val)
    not regex.match("^(TODO|FIXME|YOUR[_-].*|CHANGE[_-].*|EXAMPLE|DUMMY|TEST|PLACEHOLDER|INSERT|REPLACE|N/A|NA|NONE|NULL|true|false|yes|no|on|off|0|1)$", lower(val))
    not is_file_path(val)
}

is_file_path(val) {
    regex.match("^(?:/|\\.\\./|\\.\\./|[a-zA-Z]:\\\\\\\\|conf/|./|file://|/etc/|/var/|/usr/|/opt/|/home/)", val)
}

contains_credential_keyword(name) {
    lower_name := lower(name)
    some kw
    credential_keywords[kw]
    lower_name == kw
}

contains_credential_keyword(name) {
    lower_name := lower(name)
    some kw
    credential_keywords[kw]
    endswith(lower_name, concat("", ["_", kw]))
}

contains_credential_keyword(name) {
    lower_name := lower(name)
    some kw
    credential_keywords[kw]
    startswith(lower_name, concat("", [kw, "_"]))
}

contains_credential_keyword(name) {
    lower_name := lower(name)
    some kw
    credential_keywords[kw]
    contains(lower_name, concat("", [".", kw]))
}

contains_credential_suffix(name) {
    lower_name := lower(name)
    some suffix
    credential_suffixes[suffix]
    endswith(lower_name, suffix)
}

has_sensitive_prefix(name) {
    lower_name := lower(name)
    some prefix
    sensitive_prefixes[prefix]
    startswith(lower_name, prefix)
}

is_credential_key(key_str) {
    contains_credential_suffix(key_str)
}

is_credential_key(key_str) {
    contains_credential_keyword(key_str)
    not is_non_credential_field(key_str)
}

is_credential_key(key_str) {
    has_sensitive_prefix(key_str)
}

is_special_key_in_context(key_str, sibling_names) {
    lower_key := lower(key_str)
    lower_key == "key"
    some sibling
    sibling_names[sibling]
    some ctx_kw
    auth_context_keywords[ctx_kw]
    regex.match(sprintf(".*%s.*", [ctx_kw]), lower(sibling))
}

is_special_key_in_context(key_str, sibling_names) {
    lower_key := lower(key_str)
    lower_key == "secret"
    some sibling
    sibling_names[sibling]
    some ctx_kw
    auth_context_keywords[ctx_kw]
    regex.match(sprintf(".*%s.*", [ctx_kw]), lower(sibling))
}

is_non_credential_field(name) {
    lower_name := lower(name)
    lower_name == "key"
}

is_non_credential_field(name) {
    lower_name := lower(name)
    startswith(lower_name, "ssh_")
    endswith(lower_name, "_key")
}

is_non_credential_field(name) {
    lower_name := lower(name)
    regex.match("^(public_key|authorized_keys?|known_hosts|key_file|key_path|key_name|api_version|auth_type|auth_method|auth_version|auth_strategy)$", lower_name)
}

is_non_credential_field(name) {
    regex.match("^(user|username|uid|principal|subject)$", lower(name))
}

get_sibling_keys(hash_entries, current_idx) = sibling_keys {
    sibling_keys = {lower(hash_entries[j].key.value) |
        some j
        j != current_idx
        j < count(hash_entries)
        hash_entries[j].key.ir_type == "String"
    }
}

check_hash_entries_for_creds(entries, path_prefix) = creds {
    creds = {cred |
        some i
        entry := entries[i]
        entry.key.ir_type == "String"
        key_str := entry.key.value
        
        entry.value.ir_type == "String"
        val_str := entry.value.value
        is_likely_secret_value(val_str)
        
        key_match(key_str, entries, i)
        
        cred = {
            "key": key_str,
            "val_node": entry.value
        }
    }
}

key_match(key_str, entries, idx) {
    is_credential_key(key_str)
}

key_match(key_str, entries, idx) {
    sibling_keys := get_sibling_keys(entries, idx)
    is_special_key_in_context(key_str, sibling_keys)
}

collect_all_creds(node) = all_creds {
    all_creds = {cred |
        some _, n
        walk(node, [_, n])
        n.ir_type == "Hash"
        count(n.value) > 0
        creds := check_hash_entries_for_creds(n.value, "")
        cred := creds[_]
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    is_credential_key(var.name)
    var.value.ir_type == "String"
    is_likely_secret_value(var.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Hard-coded credentials in source code can lead to security vulnerabilities. Use external secret management systems. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    
    all_creds := collect_all_creds(var.value)
    cred := all_creds[_]
    
    result := {
        "type": "sec_hard_secr",
        "element": cred.val_node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Hard-coded credentials in source code can lead to security vulnerabilities. Use external secret management systems. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    au := parent.atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_credential_key(attr.name)
    attr.value.ir_type == "String"
    is_likely_secret_value(attr.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Hard-coded credentials in source code can lead to security vulnerabilities. Use external secret management systems. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    au := parent.atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    all_creds := collect_all_creds(attr.value)
    cred := all_creds[_]
    
    result := {
        "type": "sec_hard_secr",
        "element": cred.val_node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Hard-coded credentials in source code can lead to security vulnerabilities. Use external secret management systems. (CWE-798)"
    }
}