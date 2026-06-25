package glitch

import data.glitch_lib

binding_keywords := {"listenaddr", "listen_address", "listenaddress", "bind_address", "bindaddr", "bind_ip", "bindip", "host", "address", "ip"}

unrestricted_values := {"0.0.0.0", "::", "::0", "*"}

cidr_keywords := {"cidr"}

all_variables_in(node) = vars {
    vars := {n |
        walk(node, [_, n])
        n.ir_type == "Variable"
        n.value.ir_type != "BlockExpr"
    }
}

is_unrestricted_string(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    unrestricted_values[lower_val]
}

name_contains_keyword(name, keywords) {
    keyword := keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_contains_keyword(attr.name, binding_keywords)
    walk(attr.value, [_, n])
    is_unrestricted_string(n)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to unrestricted IP address (0.0.0.0 or ::) - Services should not listen on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_contains_keyword(attr.name, cidr_keywords)
    walk(attr.value, [_, n])
    is_unrestricted_string(n)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive network rule allowing traffic from unrestricted source addresses - Firewall rules should restrict source addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := all_variables_in(parent)
    var := vars[_]
    name_contains_keyword(var.name, binding_keywords)
    walk(var.value, [_, n])
    is_unrestricted_string(n)
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to unrestricted IP address (0.0.0.0 or ::) - Services should not listen on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := all_variables_in(parent)
    var := vars[_]
    name_contains_keyword(var.name, cidr_keywords)
    walk(var.value, [_, n])
    is_unrestricted_string(n)
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Overly permissive network rule allowing traffic from unrestricted source addresses - Firewall rules should restrict source addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    is_unrestricted_string(n)
    result := {
        "type": "sec_invalid_bind",
        "element": n,
        "path": parent.path,
        "description": "Unrestricted IP address binding (0.0.0.0 or ::) detected in configuration - Services should not listen on all network interfaces. (CWE-1327)"
    }
}