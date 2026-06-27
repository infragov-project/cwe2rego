package glitch

import data.glitch_lib
import future.keywords.in

credential_keywords := {"password", "passwd", "pwd", "secret", "token", "key", "apikey", "api_key", "access_key", "secret_key", "credential", "credentials", "keystore_password", "truststore_password", "sha512_password"}

is_sensitive_key(name) {
    lower_name := lower(name)
    kw := credential_keywords[_]
    contains(lower_name, kw)
}

is_safe_reference(val) {
    val.ir_type == "VariableReference"
} else {
    val.ir_type == "FunctionCall"
} else {
    val.ir_type == "Access"
}

is_path_value(val) {
    val.ir_type == "String"
    regex.match(`^(\/|\\|[a-zA-Z]:\\|\.{0,2}\/|.*\.(crt|key|pem|jks|p12|pfx))`, val.value)
}

is_trivial_value(val) {
    val.ir_type == "String"
    count(val.value) < 4
} else {
    val.ir_type == "String"
    regex.match(`^(true|false|null|undefined|none|nil|yes|no|on|off)$`, lower(val.value))
}

should_detect_credential(key_str, val) {
    not is_safe_reference(val)
    val.ir_type == "String"
    val.value != ""
    not is_trivial_value(val)
    is_sensitive_key(key_str)
    not is_path_value(val)
}

find_all_hash_entries[entry] {
    walk(input, [path, node])
    node.ir_type == "Hash"
    some item in node.value
    item.ir_type == "KeyValue"
    entry := item
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    entry := find_all_hash_entries[_]
    key_str := entry.key.value
    val := entry.value
    
    should_detect_credential(key_str, val)
    
    result := {
        "type": "sec_hard_secr",
        "element": {
            "ir_type": "KeyValue",
            "line": val.line,
            "column": val.column,
            "end_line": val.end_line,
            "end_column": val.end_column,
            "code": val.code,
            "key": entry.key,
            "value": val
        },
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding credentials directly in source code. Use secure credential management instead. (CWE-798)"
    }
}