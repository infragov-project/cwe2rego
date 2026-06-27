package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "secret", "credential", "auth", "authentication", "passphrase", "passcode", "token", "key"}

activation_patterns := {"activationkey", "activation_key", "license_key", "licensekey", "product_key", "productkey", "subscription_key", "activation-token"}

proxy_patterns := {"proxy_password", "proxy-secret", "proxy_token", "proxy_key"}

is_password_related(name) {
    kw := password_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), name)
    not is_activation_key(name)
    not is_proxy_field(name)
}

is_activation_key(name) {
    ap := activation_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [ap]), name)
}

is_proxy_field(name) {
    pp := proxy_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pp]), name)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

is_safe_reference(value) {
    value.ir_type == "FunctionCall"
    regex.match("(?i)(vault|secret|lookup|env|kms|encrypt|hash)", value.name)
}

is_safe_reference(value) {
    value.ir_type == "VariableReference"
    regex.match("(?i)(vault|secret|kms|encrypt|hash)", value.value)
}

check_value_empty(value) {
    is_empty_value(value)
    not is_safe_reference(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_password_related(var.name)
    check_value_empty(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_password_related(attr.name)
    check_value_empty(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password or credential fields should not be empty. (CWE-258)"
    }
}