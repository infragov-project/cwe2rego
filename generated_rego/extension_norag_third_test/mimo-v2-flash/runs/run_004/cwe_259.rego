package glitch

import data.glitch_lib

sensitive_fields := {"password", "secret", "token", "key", "credential", "auth", "private", "pwd", "pass"}

is_sensitive_field(name) {
    lower_name := lower(name)
    some field
    sensitive_fields[field]
    contains(lower_name, field)
}

is_hardcoded_secret(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not regex.match("^(var\\.|data\\.|secretsmanager\\.|environment_variable|env\\.|reference\\.|get_param|list_key|join\\(|concat\\(|split\\(|lookup\\()", lower(value.value))
}

is_common_password(value) {
    value.ir_type == "String"
    regex.match("(?i)^(password|admin|root|123456|secret|letmein|welcome|passw0rd|qwerty|12345|1234)$", value.value)
}

is_base64_encoded(value) {
    value.ir_type == "String"
    regex.match("^[A-Za-z0-9+/]{20,}={0,2}$", value.value)
}

is_ip_address(value) {
    value.ir_type == "String"
    regex.match("^([0-9]{1,3}\\.){3}[0-9]{1,3}$", value.value)
}

is_port(value) {
    value.ir_type == "Integer"
    value.value >= 0
    value.value <= 65535
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_sensitive_field(v.name)
    is_hardcoded_secret(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": sprintf("Use of Hardcoded Password - Variable '%s' contains hardcoded credential. (CWE-259)", [v.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_base64_encoded(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hardcoded Password - Inline Base64 encoded secret detected. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_sensitive_field(v.name)
    is_common_password(v.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hardcoded Password - Common hardcoded credential detected. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_sensitive_field(attr.name)
    is_hardcoded_secret(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of Hardcoded Password - Attribute '%s' contains hardcoded credential. (CWE-259)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_base64_encoded(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hardcoded Password - Inline Base64 encoded secret detected. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_sensitive_field(attr.name)
    is_common_password(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hardcoded Password - Common hardcoded credential detected. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_sensitive_field(v.name)
    v.value.ir_type == "String"
    regex.match("://.*:.*@", v.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of Hardcoded Password - Embedded authentication in connection string. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_sensitive_field(attr.name)
    attr.value.ir_type == "String"
    regex.match("://.*:.*@", attr.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hardcoded Password - Embedded authentication in connection string. (CWE-259)"
    }
}