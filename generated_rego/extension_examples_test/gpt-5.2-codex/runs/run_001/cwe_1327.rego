package glitch

import data.glitch_lib

is_hosts_key(n) { n == "hosts" }
is_hosts_key(n) { n == ":hosts" }

is_binding_name(name) {
    is_string(name)
    n := lower(name)
    not is_hosts_key(n)
    regex.match("(bind|listen|address|addr|interface|endpoint|expose|publish|ingress)", n)
}
is_binding_name(name) {
    is_string(name)
    n := lower(name)
    not is_hosts_key(n)
    regex.match("(^|[^a-z0-9])ip([^a-z0-9]|$)", n)
}
is_binding_name(name) {
    is_string(name)
    n := lower(name)
    not is_hosts_key(n)
    regex.match("(^|[^a-z0-9])host(name)?([^a-z0-9]|$)", n)
}

is_unrestricted_string(s) {
    is_string(s)
    v := lower(s)
    regex.match("^\\s*$", v)
} else {
    is_string(s)
    v := lower(s)
    regex.match("^\\s*any\\s*$", v)
} else {
    is_string(s)
    v := lower(s)
    regex.match("^\\s*all\\s*$", v)
} else {
    is_string(s)
    v := lower(s)
    regex.match("^\\s*\\*($|\\s|:)", v)
} else {
    is_string(s)
    v := lower(s)
    regex.match("(^|[^0-9\\.])0\\.0\\.0\\.0($|[^0-9\\.])", v)
} else {
    is_string(s)
    v := lower(s)
    regex.match("^\\s*::\\s*$", v)
} else {
    is_string(s)
    v := lower(s)
    regex.match("^\\s*::/0\\s*$", v)
} else {
    is_string(s)
    v := lower(s)
    regex.match("\\[::\\]", v)
}

unrestricted_in_expr(expr) {
    walk(expr, [_, v])
    v.ir_type == "String"
    is_unrestricted_string(v.value)
} else {
    walk(expr, [_, v])
    v.ir_type == "Null"
} else {
    walk(expr, [_, v])
    v.ir_type == "Undef"
}

entry_key(entry) = k {
    entry.key.ir_type == "String"
    k := entry.key.value
} else = k {
    entry.key.ir_type == "VariableReference"
    k := entry.key.value
} else = k {
    is_string(entry.name)
    k := entry.name
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    is_binding_name(attr.name)
    unrestricted_in_expr(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not listen on wildcard or unspecified addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    v := glitch_lib.all_variables(parent)[_]
    is_binding_name(v.name)
    unrestricted_in_expr(v.value)

    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not listen on wildcard or unspecified addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    key := entry_key(entry)
    is_binding_name(key)
    unrestricted_in_expr(entry.value)

    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not listen on wildcard or unspecified addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    some k
    v := h.value[k]
    is_binding_name(k)
    unrestricted_in_expr(v)

    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not listen on wildcard or unspecified addresses. (CWE-1327)"
    }
}