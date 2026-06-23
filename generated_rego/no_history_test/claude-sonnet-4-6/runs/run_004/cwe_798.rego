package glitch

import data.glitch_lib

sensitive_name_pattern := "(?i).*(password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key|signing_key|encryption_key|connection_string|connectionstring|db_url|database_url|jdbc_url|client_secret|webhook_secret|ssh_password|ssh_private_key|hmac_key|aes_key|auth_key|account_key|registry_password|admin_password|root_password|db_password|bootstrap_password|keystore|truststore|credential|passphrase|certificate|cert|user|username|key).*"

file_field_exclusion_pattern := "(?i).*(_(xml|html|template|dir|log|path|file|conf|config|script|manifest)s?$)"

safe_value_pattern := "(?i).*(\\$\\{|vault\\(|ssm:|keyvault:|\\$\\(|\\{\\{|<%).*"

is_sensitive_name(name) {
    regex.match(sensitive_name_pattern, name)
    not regex.match(file_field_exclusion_pattern, name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match(safe_value_pattern, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_sensitive_name(v.name)
    is_hardcoded_string(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be stored as plain-text literals in IaC scripts. (CWE-798)"
    }
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
        "description": "Use of hard-coded credentials - Credentials should not be stored as plain-text literals in IaC scripts. (CWE-798)"
    }
}