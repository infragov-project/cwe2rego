package glitch

import data.glitch_lib

sensitive_field_regex := "(?i).*(password|passwd|passphrase|secret|access_token|auth_token|bearer_token|api_key|apikey|api_secret|client_secret|private_key|signing_key|connection_string|conn_str|database_url|db_url|login_password|user_password).*"

dynamic_ref_regex := "(?i).*(\\$\\{|\\{\\{|\\$\\(|arn:|vault:|kms:|ENC\\[|AES256:).*"

is_sensitive_field(name) {
    regex.match(sensitive_field_regex, name)
}

is_hardcoded_literal(val) {
    val.ir_type == "String"
    val.value != ""
    not regex.match(dynamic_ref_regex, val.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_field(attr.name)
    is_hardcoded_literal(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_sensitive_field(var.name)
    is_hardcoded_literal(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(pwd=|password=|passwd=)[^;\\s]+.*", attr.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password in connection string - Credentials embedded in connection strings. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    regex.match("(?i).*(pwd=|password=|passwd=)[^;\\s]+.*", var.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password in connection string - Credentials embedded in connection strings. (CWE-259)"
    }
}