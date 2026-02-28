package glitch

import data.glitch_lib

literal_types := {"String", "Integer", "Float", "Boolean", "Complex"}

desc := "Use of hard-coded password or secret - Sensitive credentials should not be hard-coded in IaC. (CWE-259)"

is_sensitive_name(name) {
    regex.match("(?i).*(password|passwd|pwd|passphrase|secret|token|credential|api[_-]?key|access[_-]?key|secret[_-]?key|shared[_-]?key|private[_-]?key|client[_-]?secret|bootstrap_password|default_password|initial_password|admin_password|root_password|master_password|db_password|user_password|login_password|ssh_password|ftp_password|auth_password|root_user|admin_user|enable_default_user).*", name)
}

is_sensitive_name(name) {
    regex.match("(?i).*([^A-Za-z0-9]|^)key([^A-Za-z0-9]|$).*", name)
}

all_keyvalues(parent) = kvs {
    kvs := {kv |
        walk(parent, [_, kv])
        glitch_lib.is_ir_type_in(kv, {"Attribute", "Variable"})
        kv.value.ir_type != "BlockExpr"
    }
}

is_hardcoded_value(val) {
    glitch_lib.traverse_var(val)
    val.ir_type != "Null"
    val.ir_type != "Undef"
    glitch_lib.is_ir_type_in(val, literal_types)
}

is_hardcoded_value(val) {
    glitch_lib.traverse_var(val)
    val.ir_type != "Null"
    val.ir_type != "Undef"
    walk(val, [_, n])
    n.ir_type == "String"
}

embedded_cred_string(s) {
    regex.match("(?i).*://[^/\\s]+:[^@/\\s]+@.*", s)
}

embedded_cred_string(s) {
    regex.match("(?i).*\\b(user(name)?|password|passwd|pwd|passphrase|token|api[_-]?key|access[_-]?key|secret|client[_-]?secret|shared[_-]?key)\\b\\s*[:=]\\s*['\"]?[^\\s\"']+['\"]?.*", s)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]
    is_sensitive_name(kv.name)
    is_hardcoded_value(kv.value)
    result := {
        "type": "sec_hard_pass",
        "element": kv,
        "path": parent.path,
        "description": desc
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]
    walk(kv.value, [_, h])
    h.ir_type == "Hash"
    pair := h.value[_]
    pair.key.ir_type == "String"
    is_sensitive_name(pair.key.value)
    val_node := pair.value
    is_hardcoded_value(val_node)
    result := {
        "type": "sec_hard_pass",
        "element": val_node,
        "path": parent.path,
        "description": desc
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_keyvalues(parent)
    kv := kvs[_]
    walk(kv.value, [_, n])
    n.ir_type == "String"
    embedded_cred_string(n.value)
    result := {
        "type": "sec_hard_pass",
        "element": n,
        "path": parent.path,
        "description": desc
    }
}