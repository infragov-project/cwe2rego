package glitch

import data.glitch_lib

sensitive_contexts = {
    "password", "secret", "key", "token", "credential", "auth", "passphrase", 
    "secret_key", "api_key", "access_key", "secret_value", "encrypted_password",
    "ssh_key", "private_key", "admin_password", "db_user", "db_pass", 
    "api_token", "bearer_token", "access_token", "refresh_token", "github_token",
    "client_secret", "cert", "pem", "key_material", "ssh_public_key", 
    "sha512_password", "tls_cacertfile"
}

default_credentials = {
    "admin", "root", "default", "demo", "test", "guest", "password", "changeme", 
    "redhat1!", "sensu", "telarista", "redhat1"
}

api_token_prefixes = {"ghp_", "AKIA", "ASIA", "gho_", "ghu_", "github_", "Bearer ", "ghr_"}

base64_functions = {"base64", "b64encode", "base64decode"}

suspicious_filenames = {"credentials", "secret", "key", "token", "id_rsa", "id_dsa", "known_hosts", "ca.crt"}

is_sensitive_value(value) {
    lower_value := lower(value)
    default_credentials[lower_value]
} else {
    contains(value, "\n")
} else {
    contains(value, "-----BEGIN")
} else {
    count(value) > 50
    regex.match("^[A-Za-z0-9+/=]+$", value)
} else {
    count(value) >= 20
    prefix := api_token_prefixes[_]
    startswith(value, prefix)
} else {
    count(value) >= 30
    regex.match("^[A-Za-z0-9_-]+$", value)
}

is_suspicious_file(value) {
    lower_value := lower(value)
    keyword := suspicious_filenames[_]
    contains(lower_value, keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some var in parent.variables
    var.ir_type == "Variable"
    lower(var.name) in sensitive_contexts
    var.value.ir_type == "String"
    is_sensitive_value(var.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in variable '%s'. (CWE-798)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some attr in parent.attributes
    attr.ir_type == "Attribute"
    lower(attr.name) in sensitive_contexts
    attr.value.ir_type == "String"
    is_sensitive_value(attr.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in attribute '%s'. (CWE-798)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some kv in node.value
    kv.key.ir_type == "String"
    lower_key := lower(kv.key.value)
    lower_key in sensitive_contexts
    kv.value.ir_type == "String"
    is_sensitive_value(kv.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": kv.value,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in hash key '%s'. (CWE-798)", [kv.key.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    node.name in base64_functions
    count(node.args) > 0
    arg := node.args[0]
    arg.ir_type == "String"
    is_sensitive_value(arg.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Base64 encoded secret with hard-coded value. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some kv in node.value
    kv.key.ir_type == "String"
    lower_key := lower(kv.key.value)
    lower_key in {"env", "environment"}
    kv.value.ir_type == "Hash"
    some env_kv in kv.value.value
    env_kv.key.ir_type == "String"
    env_kv.value.ir_type == "String"
    is_sensitive_value(env_kv.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": env_kv.value,
        "path": parent.path,
        "description": sprintf("Hard-coded credential in environment variable '%s'. (CWE-798)", [env_kv.key.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some kv in node.value
    kv.key.ir_type == "String"
    lower_key := lower(kv.key.value)
    lower_key in {"file", "include", "source", "path"}
    kv.value.ir_type == "String"
    is_suspicious_file(kv.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": kv.value,
        "path": parent.path,
        "description": sprintf("Suspicious file reference '%s' might contain credentials. (CWE-798)", [kv.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some kv in node.value
    kv.key.ir_type == "String"
    lower_key := lower(kv.key.value)
    lower_key in {"sha512_password"}
    kv.value.ir_type == "String"
    not is_sensitive_value(kv.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": kv.value,
        "path": parent.path,
        "description": sprintf("Hashed password found in key '%s'. (CWE-798)", [kv.key.value])
    }
}