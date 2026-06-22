package glitch

import data.glitch_lib

credential_terms := {"password", "pwd", "passwd", "pass", "secret", "secret_key", "secret_token", "token", "api_key", "api_token", "auth_token", "access_key", "access_token", "private_key", "credential", "credentials", "passphrase", "key", "keystore_password", "truststore_password", "keystore", "truststore", "encryption_key", "signing_key", "master_key", "root_key", "admin_key", "user_key", "krb_password", "krb_key", "bootstrap_token", "join_token", "enrollment_token", "vault_token"}

is_credential_term(name) {
    term := credential_terms[_]
    regex.match(term, lower(name))
}

is_likely_secret_value(val) {
    count(val) >= 6
    not is_common_placeholder(val)
    not is_ldap_dn_pattern(val)
    not is_ldap_attr_value(val)
    not is_boolean_string(val)
    not is_simple_path(val)
}

is_likely_secret_value(val) {
    regex.match("^[A-Za-z0-9+/]{12,}={0,2}$", val)
}

is_likely_secret_value(val) {
    regex.match("^\\$[0-9a-zA-Z]+\\$[./A-Za-z0-9]+$", val)
}

is_common_placeholder(val) {
    lower_val := lower(val)
    placeholders := {"null", "none", "undefined", "default", "example", "sample", "test", "testing", "dummy", "placeholder", "changeme", "change_me", "changeme123", "true", "false", "yes", "no", "on", "off"}
    lower_val == placeholders[_]
} else {
    regex.match("^[a-z]+[0-9]+$", lower(val))
}

is_ldap_dn_pattern(val) {
    regex.match("^uid=[^,]+,cn=[^,]+,dc=", val)
} else {
    regex.match("^cn=[^,]+,dc=.*dc=", val)
} else {
    regex.match("^ou=[^,]+,", val)
}

is_ldap_attr_value(val) {
    lower_val := lower(val)
    ldap_vals := {"uid", "cn", "dc", "ou", "o", "mail", "description", "member", "groupofnames", "person", "nsaccountlock", "true", "false"}
    lower_val == ldap_vals[_]
} else {
    regex.match("^[^@]+@[^@]+\\.[^@]+$", val)
}

is_boolean_string(val) {
    lower(val) == "true"
} else {
    lower(val) == "false"
}

is_simple_path(val) {
    regex.match("^(/[^/ ]+)+\\.?[a-z]*$", val)
}

get_string_from_node(node) = s {
    node.ir_type == "String"
    s = node.value
} else = s {
    node.ir_type == "VariableReference"
    s = node.value
} else = "" {
    true
}

check_node_for_credential(node) {
    node.ir_type == "Hash"
    some i
    entry := node.value[i]
    entry.ir_type == "KeyValue"
    key_str := get_string_from_node(entry.key)
    is_credential_term(key_str)
    val_node := entry.value
    val_node.ir_type == "String"
    val_str := val_node.value
    val_str != ""
    is_likely_secret_value(val_str)
}

check_node_for_credential(node) {
    node.ir_type == "KeyValue"
    key_str := get_string_from_node(node.key)
    is_credential_term(key_str)
    val_node := node.value
    val_node.ir_type == "String"
    val_str := val_node.value
    val_str != ""
    is_likely_secret_value(val_str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Hash"
    some i
    entry := node.value[i]
    entry.ir_type == "KeyValue"
    key_str := get_string_from_node(entry.key)
    is_credential_term(key_str)
    val_node := entry.value
    val_node.ir_type == "String"
    val_str := val_node.value
    val_str != ""
    is_likely_secret_value(val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": entry,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials are hard-coded in the configuration, which may allow attackers to bypass authentication and gain unauthorized access. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "KeyValue"
    key_str := get_string_from_node(node.key)
    is_credential_term(key_str)
    val_node := node.value
    val_node.ir_type == "String"
    val_str := val_node.value
    val_str != ""
    is_likely_secret_value(val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials are hard-coded in the configuration, which may allow attackers to bypass authentication and gain unauthorized access. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    var_name := var.name
    is_credential_term(var_name)
    var.value.ir_type == "String"
    val := var.value.value
    val != ""
    is_likely_secret_value(val)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials are hard-coded in the configuration, which may allow attackers to bypass authentication and gain unauthorized access. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    var := parent.variables[_]
    walk(var.value, [_, node])
    check_node_for_credential(node)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials are hard-coded in the configuration, which may allow attackers to bypass authentication and gain unauthorized access. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    au := parent.atomic_units[_]
    attr := au.attributes[_]
    attr_name := attr.name
    is_credential_term(attr_name)
    attr.value.ir_type == "String"
    val := attr.value.value
    val != ""
    is_likely_secret_value(val)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials are hard-coded in the configuration, which may allow attackers to bypass authentication and gain unauthorized access. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    au := parent.atomic_units[_]
    walk(au, [_, node])
    check_node_for_credential(node)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials are hard-coded in the configuration, which may allow attackers to bypassauthentication and gain unauthorized access. (CWE-798)"
    }
}