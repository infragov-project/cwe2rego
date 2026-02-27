package glitch

import data.glitch_lib

bind_attr_keywords := {
    "listen", "bind", "addr", "address", "host", "ip",
    "server", "interface", "iface", "source"
}

wildcard_str_values := {"0.0.0.0", "::", "0:0:0:0:0:0:0:0", "*"}

is_bind_attr_name(name) {
    lower_name := lower(name)
    keyword := bind_attr_keywords[_]
    contains(lower_name, keyword)
}

is_wildcard_str(val) {
    wildcard_str_values[val]
}

is_wildcard_str(val) {
    startswith(val, "0.0.0.0/")
}

is_wildcard_str(val) {
    startswith(val, "::/")
}

is_wildcard_value(value) {
    value.ir_type == "String"
    is_wildcard_str(value.value)
}

# Pattern 1: glitch_lib all_atomic_units, direct bind attr
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    node := glitch_lib.all_atomic_units(parent)[_]
    attr := node.attributes[_]
    is_bind_attr_name(attr.name)
    is_wildcard_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 2: glitch_lib all_atomic_units, Hash attr - report entry.key
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    node := glitch_lib.all_atomic_units(parent)[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    is_bind_attr_name(entry.key.value)
    is_wildcard_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.key,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 3: glitch_lib parent.atomic_units, direct bind attr
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    node := parent.atomic_units[_]
    attr := node.attributes[_]
    is_bind_attr_name(attr.name)
    is_wildcard_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 4: glitch_lib parent.atomic_units, Hash attr - report entry.key
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    node := parent.atomic_units[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    is_bind_attr_name(entry.key.value)
    is_wildcard_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.key,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 5: glitch_lib parent.variables Hash - report entry.key (Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    var := parent.variables[_]
    var.value.ir_type == "Hash"
    entry := var.value.value[_]
    is_bind_attr_name(entry.key.value)
    is_wildcard_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.key,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 6: root input.atomic_units, direct bind attr
Glitch_Analysis[result] {
    node := input.atomic_units[_]
    attr := node.attributes[_]
    is_bind_attr_name(attr.name)
    is_wildcard_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": input.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 7: root input.atomic_units, Hash attr - report entry.key
Glitch_Analysis[result] {
    node := input.atomic_units[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    is_bind_attr_name(entry.key.value)
    is_wildcard_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.key,
        "path": input.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 8: root input.variables Hash - report entry.key (Chef root)
Glitch_Analysis[result] {
    var := input.variables[_]
    var.value.ir_type == "Hash"
    entry := var.value.value[_]
    is_bind_attr_name(entry.key.value)
    is_wildcard_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.key,
        "path": input.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 9: unit_blocks depth 1, atomic_units, direct bind attr (Puppet)
Glitch_Analysis[result] {
    ub := input.unit_blocks[_]
    node := ub.atomic_units[_]
    attr := node.attributes[_]
    is_bind_attr_name(attr.name)
    is_wildcard_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": ub.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 10: unit_blocks depth 1, atomic_units, Hash attr - report entry.key
Glitch_Analysis[result] {
    ub := input.unit_blocks[_]
    node := ub.atomic_units[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    is_bind_attr_name(entry.key.value)
    is_wildcard_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.key,
        "path": ub.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}

# Pattern 11: unit_blocks depth 1, variables Hash - report entry.key
Glitch_Analysis[result] {
    ub := input.unit_blocks[_]
    var := ub.variables[_]
    var.value.ir_type == "Hash"
    entry := var.value.value[_]
    is_bind_attr_name(entry.key.value)
    is_wildcard_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.key,
        "path": ub.path,
        "description": "Binding to an Unrestricted IP Address - A network service is configured to listen on all interfaces using a wildcard address (e.g., 0.0.0.0), exposing it to unintended networks. (CWE-1327)"
    }
}