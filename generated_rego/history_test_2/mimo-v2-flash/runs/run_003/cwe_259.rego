package glitch

import data.glitch_lib

hardcoded_password_keywords := {"password", "secret", "secretKey", "token", "credential", "credentials", "auth", "authentication", "key", "passwd", "pwd", "username", "admin", "connection_string", "bind_password", "api_key", "api_secret"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    lower_name := lower(attr.name)
    contains(lower_name, hardcoded_password_keywords[_])
    
    value_type := attr.value.ir_type
    (value_type == "String" and attr.value.value != "") or (value_type == "Hash") or (value_type == "Array")
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - The application contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own authentication and for performing security-critical functions. (CWE-259)"
    }
}