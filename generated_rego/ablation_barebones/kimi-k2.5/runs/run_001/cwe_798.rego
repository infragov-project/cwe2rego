package glitch

import data.glitch_lib

# Common secret keywords that indicate hardcoded credentials
secret_key_names := {"password", "pwd", "pass", "secret", "token", "key", "api_key", "apikey", "auth", "credential", "access_key", "secret_key", "private_key", "passwd", "Password", "Pwd", "Pass", "Secret", "Token", "Key", "ApiKey", "Api_Key", "Auth", "Credential", "Access_Key", "Secret_Key", "Private_Key", "Passwd"}

# Check if attribute name contains secret-related keywords
is_secret_attribute(name) {
    name == secret_key_names[_]
} else {
    regex.match("(?i).*(password|pwd|pass|secret|token|key|credential|auth).*", name)
}

# Check if value is a hardcoded string (not empty, not a variable reference)
is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_secret_attribute(attr.name)
    is_hardcoded_string(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials such as passwords, API keys, or tokens should not be hardcoded in configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_secret_attribute(var.name)
    is_hardcoded_string(var.value)

    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials such as passwords, API keys, or tokens should not be hardcoded in configuration. (CWE-798)"
    }
}