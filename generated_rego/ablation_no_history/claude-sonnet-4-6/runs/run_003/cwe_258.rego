package glitch

import data.glitch_lib

is_password_field(name) {
    regex.match("(?i).*(password|passwd|pass|pwd|secret|token|activationkey|activation_key|api_key|auth_key|access_key|private_key|secret_key|license_key|signing_key|shared_secret|bind_password|keystore_password|truststore_password).*", name)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_value(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - A password attribute is assigned an empty value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field(v.name)
    is_empty_value(v.value)

    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration - A password variable is assigned an empty value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ub_attr := parent.attributes[_]
    is_password_field(ub_attr.name)
    is_empty_value(ub_attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": ub_attr,
        "path": parent.path,
        "description": "Empty password parameter in configuration - A password parameter is assigned an empty default value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(password|passwd|pwd)=;|(password|passwd|pwd)=$", attr.value.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - A connection string contains an empty password segment. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    regex.match("(?i)(no_password|passwordless|allow_empty_password)", attr.name)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password explicitly enabled - A configuration flag allows empty or no password authentication. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    regex.match("(?i)require_password", attr.name)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Password requirement disabled - A configuration flag explicitly disables password authentication. (CWE-258)"
    }
}