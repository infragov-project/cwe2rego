package glitch

import data.glitch_lib
import future.keywords.in

credential_keywords := {
    "password",
    "passwd",
    "pwd",
    "secret",
    "secret_key",
    "private_key",
    "encryption_key",
    "signing_key",
    "master_key",
    "api_key",
    "access_key",
    "secret_access_key",
    "auth_token",
    "bearer_token",
    "client_secret",
    "connection_string",
    "root_password",
    "admin_password",
    "sha512_password",
    "sha256_password",
    "crypt_password",
    "ssh_password",
    "pass",
    "token",
    "credential",
}

keystore_password_patterns := {
    "keystore_password",
    "truststore_password",
}

is_credential_field(name) {
    lower_name := lower(name)
    some keyword in credential_keywords
    contains(lower_name, keyword)
}

is_keystore_password_field(name) {
    lower_name := lower(name)
    some pattern in keystore_password_patterns
    contains(lower_name, pattern)
}

is_not_reference(val) {
    lower_val := lower(val)
    not startswith(lower_val, "var.")
    not startswith(lower_val, "data.")
    not startswith(lower_val, "vault_")
    not startswith(val, "${")
    not startswith(val, "$")
    not startswith(val, "{{")
    not contains(lower_val, "lookup(")
    not contains(lower_val, "ansible_vault")
    not contains(lower_val, "secrets_manager")
    not contains(lower_val, "key_vault")
    not contains(lower_val, "parameter_store")
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    count(value.value) > 0
    is_not_reference(value.value)
}

check_credential_kv(key_value) {
    key_value.ir_type == "KeyValue"
    key_value.key.ir_type == "String"
    key_value.value.ir_type == "String"
    is_hardcoded_string(key_value.value)
    is_credential_field(key_value.key.value)
}

check_credentials_in_hash(hash_value) {
    hash_value.ir_type == "Hash"
    some entry in hash_value.value
    check_credential_kv(entry)
}

collect_all_nested_credentials(node) = credentials {
    credentials := {cred |
        [path, n] := walk(node)
        n.ir_type == "KeyValue"
        n.key.ir_type == "String"
        n.value.ir_type == "String"
        is_hardcoded_string(n.value)
        key_name := n.key.value
        is_credential_field(key_name)
        cred := {
            "key": key_name,
            "value": n.value,
        }
    }
}

collect_keystore_nested_credentials(node) = credentials {
    credentials := {cred |
        [path, n] := walk(node)
        n.ir_type == "KeyValue"
        n.key.ir_type == "String"
        n.value.ir_type == "String"
        is_hardcoded_string(n.value)
        key_name := n.key.value
        is_keystore_password_field(key_name)
        cred := {
            "key": key_name,
            "value": n.value,
        }
    }
}

find_credential_in_node(node, name) = result {
    node.ir_type == "String"
    is_hardcoded_string(node)
    is_credential_field(name)
    result := {
        "key": name,
        "value": node,
    }
}

check_any_value_recursive(node) = results {
    results := {cred |
        [path, n] := walk(node)
        check_credential_kv(n)
        cred := {
            "key": n.key.value,
            "value": n.value,
        }
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some var in parent.variables
    var.value != null
    var.name != ""
    cred := find_credential_in_node(var.value, var.name)
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some var in parent.variables
    var.value != null
    creds := collect_all_nested_credentials(var.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some var in parent.variables
    var.value != null
    creds := collect_keystore_nested_credentials(var.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr in parent.attributes
    attr.value != null
    cred := find_credential_in_node(attr.value, attr.name)
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr in parent.attributes
    attr.value != null
    creds := collect_all_nested_credentials(attr.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr in parent.attributes
    attr.value != null
    creds := collect_keystore_nested_credentials(attr.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some au in parent.atomic_units
    some attr in au.attributes
    attr.value != null
    cred := find_credential_in_node(attr.value, attr.name)
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some au in parent.atomic_units
    some attr in au.attributes
    attr.value != null
    creds := collect_all_nested_credentials(attr.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some au in parent.atomic_units
    some attr in au.attributes
    attr.value != null
    creds := collect_keystore_nested_credentials(attr.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some ub in parent.unit_blocks
    some var in ub.variables
    var.value != null
    cred := find_credential_in_node(var.value, var.name)
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some ub in parent.unit_blocks
    some var in ub.variables
    var.value != null
    creds := collect_all_nested_credentials(var.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some ub in parent.unit_blocks
    some attr in ub.attributes
    attr.value != null
    cred := find_credential_in_node(attr.value, attr.name)
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some ub in parent.unit_blocks
    some attr in ub.attributes
    attr.value != null
    creds := collect_all_nested_credentials(attr.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some ub in parent.unit_blocks
    some subub in ub.unit_blocks
    some var in subub.variables
    var.value != null
    creds := collect_all_nested_credentials(var.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some ub in parent.unit_blocks
    some au in ub.atomic_units
    some attr in au.attributes
    attr.value != null
    creds := collect_all_nested_credentials(attr.value)
    some cred in creds
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some cond in glitch_lib.all_conditional_statements(parent)
    some cred in check_any_value_recursive(cond)
    result := {
        "type": "sec_hard_secr",
        "element": cred.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded and should use external secret management. (CWE-798)"
    }
}