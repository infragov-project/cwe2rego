package glitch

import data.glitch_lib

credential_keywords := {
    "password", "passwd", "pwd", "secret", "token", "api_key",
    "access_key", "private_key", "encryption_key", "passphrase",
    "client_secret", "signing_key", "credential", "master_key",
    "auth_token", "api_secret", "activation_key", "ssh_key",
    "tls_key", "auth_pass", "proxy_pass"
}

is_credential_field(name) {
    lower_name := lower(name)
    normalized := replace(replace(lower_name, "[", ""), "]", " ")
    keyword := credential_keywords[_]
    contains(normalized, keyword)
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

is_empty_value(value) {
    value.ir_type == "String"
    trim_space(value.value) == ""
}

# Ansible: variables in defaults files are intentional templates
is_defaults_context(path) {
    contains(lower(path), "/defaults/")
}

is_defaults_context(path) {
    contains(lower(path), "defaults-")
}

# Chef: attributes with precedence-level prefixes are template declarations
chef_precedence_prefixes := {"default[", "normal[", "override[", "force_default[", "force_override["}

is_chef_precedence_variable(name) {
    lower_name := lower(name)
    prefix := chef_precedence_prefixes[_]
    startswith(lower_name, prefix)
}

is_template_variable(var) {
    is_defaults_context(var.path)
}

is_template_variable(var) {
    is_chef_precedence_variable(var.name)
}

Glitch_Analysis[result] {
    ub := glitch_lib._gather_parent_unit_blocks[_]
    ub.path != ""

    all_vars := glitch_lib.all_variables(ub)
    var := all_vars[_]
    var.path := ub.path

    is_credential_field(var.name)
    is_empty_value(var.value)
    not is_template_variable(var)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": ub.path,
        "description": "Empty password in configuration file - Passwords and other credentials should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    ub := glitch_lib._gather_parent_unit_blocks[_]
    ub.path != ""

    all_attrs := glitch_lib.all_attributes(ub)
    attr := all_attrs[_]
    attr.path := ub.path

    is_credential_field(attr.name)
    is_empty_value(attr.value)
    not is_template_variable(attr)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": ub.path,
        "description": "Empty password in configuration file - Passwords and other credentials should not be empty. (CWE-258)"
    }
}