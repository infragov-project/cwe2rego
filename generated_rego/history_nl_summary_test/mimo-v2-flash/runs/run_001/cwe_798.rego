package glitch

import data.glitch_lib

credential_patterns := {
    "password", "secret", "key", "token", "credential", "auth", "apikey", "apitoken", 
    "secret_key", "access_key", "private_key", "passwd", "pwd", "admin_password", 
    "root_password", "initial_password", "default_credential", "master_key", "debug_token", 
    "service_account_key", "iam_secret", "cloud_credentials", "client_secret", "sha512_password",
    "truststore_password", "user", "username"
}

exclusion_patterns := {
    "{{", "env(", "secret_manager", "ssm_parameter_store", "key_vault", "azure_key_vault", 
    "gcp_secret_manager", "kms_secret", "template(", "file(", "contents =>", "content =>",
    "AllowAllAuthenticator", "AllowAllAuthorizer"
}

any_exclusion(str) {
    pattern := exclusion_patterns[_]
    glitch_lib.contains(str, pattern)
}

is_credential_name(name) {
    lower_name := lower(name)
    pattern := credential_patterns[_]
    glitch_lib.contains(lower_name, pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variable := glitch_lib.all_variables(parent)[_]
    variable.name != ""
    is_credential_name(variable.name)
    variable.value.ir_type == "String"
    value_str := variable.value.value
    value_str != ""
    not any_exclusion(value_str)
    not any_exclusion(variable.name)
    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attribute := glitch_lib.all_attributes(parent)[_]
    attribute.name != ""
    is_credential_name(attribute.name)
    attribute.value.ir_type == "String"
    value_str := attribute.value.value
    value_str != ""
    not any_exclusion(value_str)
    not any_exclusion(attribute.name)
    result := {
        "type": "sec_hard_secr",
        "element": attribute,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    value.ir_type == "String"
    is_credential_name(key.value)
    value_str := value.value
    value_str != ""
    not any_exclusion(value_str)
    not any_exclusion(key.value)
    result := {
        "type": "sec_hard_secr",
        "element": key,
        "path": parent.path,
        "description": "Hard-coded credentials detected - Avoid using hard-coded credentials. (CWE-798)"
    }
}