package glitch

import data.glitch_lib
import future.keywords.in

insecure_protocols = {"http://", "ftp://", "telnet://", "smtp://"}
security_disable_keys = {"validate_certs", "ssl", "tls_enabled", "enable_https_only", "secure_transfer", "require_secure_transfer", "https_only", "require_ssl", "ssl_mode"}
insecure_string_values = {"no", "disabled", "none", "false"}

check_string_for_insecure_protocol(str_value) {
    regex.match("^(http|ftp|telnet|smtp)://", str_value)
}

is_disable_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disable_value(value) {
    value.ir_type == "String"
    lower_case := lower(value.value)
    lower_case in insecure_string_values
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.value.ir_type == "String"
    check_string_for_insecure_protocol(attr.value.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure protocol found in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "String"
    check_string_for_insecure_protocol(var.value.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Insecure protocol found in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.name in security_disable_keys
    is_disable_value(attr.value)
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Security setting disabled in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.name in security_disable_keys
    is_disable_value(var.value)
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Security setting disabled in variable. (CWE-319)"
    }
}