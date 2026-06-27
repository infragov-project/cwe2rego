package glitch

import future.keywords.in
import data.glitch_lib

credential_keywords := {"password", "passwd", "secret", "secretkey", "secrettoken", "api_key", "apikey", "access_key", "secret_key", "private_key", "credentials", "authtoken", "api_secret", "client_secret", "consumer_secret", "sha512_password", "token", "key", "keystore", "truststore"}

is_credential_key(key) {
    lower_key := lower(key)
    some kw in credential_keywords
    contains(lower_key, kw)
}

is_var_ref(value) {
    value.ir_type == "VariableReference"
}

is_var_ref(value) {
    value.ir_type == "Undef"
}

is_var_ref(value) {
    value.ir_type == "Null"
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not is_var_ref(value)
}

get_key_string(key) = str {
    key.ir_type == "String"
    str := key.value
} else = str {
    key.ir_type == "Integer"
    str := sprintf("%d", [key.value])
} else = str {
    str := sprintf("%v", [key])
}

# Collect all key-value entries from a Hash node at given path
hash_entries(hash_node, base_path, entry) {
    some k
    e := hash_node.value[k]
    key_str := get_key_string(e.key)
    new_path := array.concat(base_path, [key_str])
    
    # Direct string value that's a credential
    e.value.ir_type == "String"
    entry := {
        "path": new_path,
        "key": key_str,
        "value": e.value,
        "entry": e
    }
}

hash_entries(hash_node, base_path, entry) {
    some k
    e := hash_node.value[k]
    key_str := get_key_string(e.key)
    new_path := array.concat(base_path, [key_str])
    
    # Nested Hash - recurse
    e.value.ir_type == "Hash"
    hash_entries(e.value, new_path, entry)
}

hash_entries(hash_node, base_path, entry) {
    some k
    e := hash_node.value[k]
    key_str := get_key_string(e.key)
    new_path := array.concat(base_path, [key_str])
    
    # Nested Array - check each element
    e.value.ir_type == "Array"
    some i
    elem := e.value.value[i]
    elem.ir_type == "Hash"
    hash_entries(elem, new_path, entry)
}

# Find credentials in any Hash structure
find_credentials_in_hash(hash_node, base_path, result) {
    some entry
    hash_entries(hash_node, base_path, entry)
    is_credential_key(entry.key)
    is_hardcoded_string(entry.value)
    result := entry
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_credential_key(node.name)
    is_hardcoded_string(node.value)

    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credentials in variable (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_credential_key(node.name)
    is_hardcoded_string(node.value)

    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credentials in attribute (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    
    some cred
    find_credentials_in_hash(node.value, [node.name], cred)
    
    result := {
        "type": "sec_hard_secr",
        "element": cred.entry,
        "path": parent.path,
        "description": sprintf("Hard-coded credentials in nested key %s (CWE-798)", [concat(".", cred.path)])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    some cred
    find_credentials_in_hash(node, [], cred)
    
    result := {
        "type": "sec_hard_secr",
        "element": cred.entry,
        "path": parent.path,
        "description": sprintf("Hard-coded credentials in nested key %s (CWE-798)", [concat(".", cred.path)])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Array"
    
    some i
    elem := node.value[i]
    elem.ir_type == "Hash"
    
    some cred
    find_credentials_in_hash(elem, [], cred)
    
    result := {
        "type": "sec_hard_secr",
        "element": cred.entry,
        "path": parent.path,
        "description": sprintf("Hard-coded credentials in nested key %s (CWE-798)", [concat(".", cred.path)])
    }
}