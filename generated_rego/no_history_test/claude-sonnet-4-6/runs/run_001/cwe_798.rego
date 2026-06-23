package glitch

import data.glitch_lib

sensitive_name_pattern := "(?i).*(password|passwd|pwd|secret_key|secret_token|secret|api_key|api_token|api_secret|access_key|access_secret|access_token|auth_token|auth_key|private_key|encryption_key|credentials?|connection_string|db_password|master_password|admin_password|client_secret|bearer_token|oauth_token|shared_secret|bind_password|signing_key|jwt_secret|ssh_key|rsa_key|hmac_secret|kms_key|deploy_key|deploy_token|webhook_secret|ssh_private_key|keystore|truststore|store_password|username|user).*"

pem_pattern := "(?s).*-----BEGIN .*(KEY|CERTIFICATE|CERT|RSA|DSA|EC|OPENSSH|PRIVATE).*-----.*"

file_ref_name_pattern := "(?i).*(file|path|dir|template|_xml|_conf|_cfg|_log|cacert|_attribute|_objectclass|_dn|_invert|_create|_update|_delete|_class|_format|_enable)$"

sensitive_name_parts := {"token", "password", "passwd", "pwd", "secret", "credential", "credentials", "keystore", "truststore", "cert", "certificate", "apikey", "accesskey", "privatekey", "authtoken", "accesstoken", "key", "user", "username"}

non_credential_suffixes := {"_name", "_domain", "_domain_name", "_type", "_id", "_label", "_tag", "_role", "_group", "_member", "_attribute", "_objectclass", "_dn", "_invert", "_create", "_update", "_delete", "_class", "_format", "_enable", "_cacert", "_cacertfile", "_file", "_path", "_dir", "_template"}

non_credential_exact := {"name", "url", "host", "port", "suffix", "dn", "member", "group", "role", "id", "type", "class", "format", "label", "tag", "domain", "description", "objectclass"}

is_non_credential_name(name) {
    endswith(lower(name), non_credential_suffixes[_])
}

is_non_credential_name(name) {
    non_credential_exact[lower(name)]
}

is_sensitive_name(name) {
    regex.match(sensitive_name_pattern, name)
    not regex.match(file_ref_name_pattern, name)
    not is_non_credential_name(name)
}

is_sensitive_name(name) {
    parts := regex.split("[^a-zA-Z0-9]+", lower(name))
    sensitive_name_parts[parts[_]]
    not regex.match(file_ref_name_pattern, name)
    not is_non_credential_name(name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not startswith(value.value, "/")
    not startswith(value.value, "./")
    not startswith(value.value, "~/")
    not startswith(value.value, "\\")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    is_sensitive_name(attr.name)
    is_hardcoded_string(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive field contains a hard-coded string literal value instead of a reference to a secret store. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    variable := vars[_]

    is_sensitive_name(variable.name)
    is_hardcoded_string(variable.value)

    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive variable contains a hard-coded string literal value instead of a reference to a secret store. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Hash"

    entry := node.value[_]
    entry.key.ir_type == "String"
    is_sensitive_name(entry.key.value)
    is_hardcoded_string(entry.value)

    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive field in nested structure contains a hard-coded string literal value. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.value.ir_type == "String"
    regex.match(pem_pattern, attr.value.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - PEM-encoded cryptographic material is hard-coded inline. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    variable := vars[_]

    variable.value.ir_type == "String"
    regex.match(pem_pattern, variable.value.value)

    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded credentials - PEM-encoded cryptographic material is hard-coded inline. (CWE-798)"
    }
}