package glitch

import data.glitch_lib

binding_keywords := {
    "bind",
    "listen",
    "address",
    "addr",
    "host",
    "interface",
    "ip",
    "service_address",
    "listener",
    "endpoint",
    "socket",
    "advertise",
    "ingress",
    "public_ip",
    "external",
    "expose",
    "source",
    "src",
    "cidr",
    "network",
    "subnet"
}

wildcard_pattern := "(?i)^\\s*(0\\.0\\.0\\.0(/0)?(:\\d+)?|::(/0)?(:\\d+)?|\\*(?::\\d+)?|any|all|0)\\s*$"

cwe_desc := "Binding to an unrestricted IP address - Service should not bind to all interfaces such as 0.0.0.0 or ::. (CWE-1327)"

is_binding_name(name) {
    kw := binding_keywords[_]
    glitch_lib.contains(name, kw)
}

binding_key_expr(key) {
    key.ir_type == "String"
    is_binding_name(key.value)
}
binding_key_expr(key) {
    key.ir_type == "VariableReference"
    is_binding_name(key.value)
}

is_unrestricted_node(n) {
    n.ir_type == "String"
    regex.match(wildcard_pattern, n.value)
}
is_unrestricted_node(n) {
    n.ir_type == "Integer"
    n.value == 0
}

# Atomic unit attributes: direct binding name with unrestricted value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]

    is_binding_name(attr.name)

    walk(attr.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# Atomic unit attributes: binding name with variable reference value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)

    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]

    is_binding_name(attr.name)

    walk(attr.value, [_, vr])
    vr.ir_type == "VariableReference"
    var_def := vars[_]
    var_def.name == vr.value

    walk(var_def.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# Atomic unit attributes: hash entry with binding key and unrestricted value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]

    walk(attr.value, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    binding_key_expr(entry.key)

    walk(entry.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# Atomic unit attributes: hash entry with binding key and variable reference value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)

    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]

    walk(attr.value, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    binding_key_expr(entry.key)

    walk(entry.value, [_, vr])
    vr.ir_type == "VariableReference"
    var_def := vars[_]
    var_def.name == vr.value

    walk(var_def.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# UnitBlock attributes: direct binding name with unrestricted value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attr := parent.attributes[_]

    is_binding_name(attr.name)

    walk(attr.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# UnitBlock attributes: binding name with variable reference value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)

    attr := parent.attributes[_]

    is_binding_name(attr.name)

    walk(attr.value, [_, vr])
    vr.ir_type == "VariableReference"
    var_def := vars[_]
    var_def.name == vr.value

    walk(var_def.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# UnitBlock attributes: hash entry with binding key and unrestricted value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attr := parent.attributes[_]

    walk(attr.value, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    binding_key_expr(entry.key)

    walk(entry.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# UnitBlock attributes: hash entry with binding key and variable reference value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)

    attr := parent.attributes[_]

    walk(attr.value, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    binding_key_expr(entry.key)

    walk(entry.value, [_, vr])
    vr.ir_type == "VariableReference"
    var_def := vars[_]
    var_def.name == vr.value

    walk(var_def.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# Variables: direct binding name with unrestricted value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var_def := vars[_]

    is_binding_name(var_def.name)

    walk(var_def.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# Variables: hash entry with binding key and unrestricted value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var_def := vars[_]

    walk(var_def.value, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    binding_key_expr(entry.key)

    walk(entry.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}

# Variables: hash entry with binding key and variable reference value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var_def := vars[_]

    walk(var_def.value, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    binding_key_expr(entry.key)

    walk(entry.value, [_, vr])
    vr.ir_type == "VariableReference"
    var_ref := vars[_]
    var_ref.name == vr.value

    walk(var_ref.value, [_, bad])
    is_unrestricted_node(bad)

    result := {
        "type": "sec_invalid_bind",
        "element": bad,
        "path": parent.path,
        "description": cwe_desc
    }
}