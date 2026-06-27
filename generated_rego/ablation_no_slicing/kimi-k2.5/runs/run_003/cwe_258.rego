package glitch

import data.glitch_lib
import future.keywords

password_patterns := {"password", "pwd", "passwd", "secret", "credential", "auth_token", "api_key", "access_key", "secret_key", "private_key", "passphrase", "admin_password", "root_password", "user_password", "db_password", "database_password", "master_password", "administrator_login_password", "rds_password", "db_instance_password", "os_profile_password", "initial_password", "temporary_password", "force_reset_password", "shared_secret", "vpn_preshared_key", "firewall_admin_pass", "token", "pw", "pass", "activationkey", "activation_key"}

weak_password_values := {"", " ", "  ", "   ", "password", "secret", "changeme", "default", "admin", "123456", "null", "nil", "none", "empty"}

is_password_field(name) {
    lower_name := lower(name)
    some pattern in password_patterns
    regex.match(sprintf(".*[_-]?%s[_-]?.*", [pattern]), lower_name)
}

has_external_lookup(val) {
    walk(val, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("^(lookup|template|vars|hiera|env|query|data)$", node.name)
}

is_weak_or_empty_value(val) {
    val.ir_type == "String"
    some weak_val in weak_password_values
    lower(val.value) == weak_val
} else {
    val.ir_type == "Null"
    not has_external_lookup(val)
} else {
    val.ir_type == "Undef"
    not has_external_lookup(val)
}

is_authentication_password(name, val) {
    lower_name := lower(name)
    not regex.match("^(username|user|email|url|host|port|path|dir|file|bucket|region|zone|id|name)$", lower_name)
    not regex.match(".*_(username|user|email|url|host|port|path|dir|file|bucket|region|zone|id|name)$", lower_name)
    not regex.match("^(emoji|icon|webhook|slack|cache|api|region|zone|ssh_|env_|apt_|docker_).*", lower_name)
    not regex.match(".*_ssh_password$", lower_name)
    not regex.match(".*_cache_.*", lower_name)
    not has_external_lookup(val)
}

collect_all_keyvalues(node) = kvs {
    kvs := {kv |
        walk(node, [_, kv])
        kv.ir_type in {"Variable", "Attribute"}
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    kv := collect_all_keyvalues(parent)[_]
    
    is_password_field(kv.name)
    is_weak_or_empty_value(kv.value)
    is_authentication_password(kv.name, kv.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": kv,
        "path": parent.path,
        "description": "Empty or weak password in configuration file - Password fields should not contain empty strings, weak defaults, or common predictable values. (CWE-258)"
    }
}