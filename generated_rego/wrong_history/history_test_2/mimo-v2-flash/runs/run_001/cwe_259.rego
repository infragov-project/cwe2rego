package glitch

import data.glitch_lib

password_keywords := {"password", "admin_password", "root_password", "db_password", "secret", "api_key", "token", "passphrase", "credential", "auth_key"}

ignore_strings := {"changeme", "<placeholder>", "example", "test"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    password_keywords[attr.name]
    attr.value.ir_type == "String"
    not ignore_strings[attr.value.value]
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in IaC scripts. (CWE-259)"
    }
}