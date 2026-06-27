package glitch

import data.glitch_lib
import future.keywords.in

description := "Binding to an unrestricted IP address - Avoid binding services to 0.0.0.0, ::, or * as this exposes them on all interfaces. (CWE-1327)"

unrestricted_ip_values := {"0.0.0.0", "::", "::0", "*", "0.0.0.0/0"}

binding_related_keywords := {
    "bind", "listen", "listenaddr", "listen_address", "binding",
    "bind_address", "listen_host", "host", "hostname", "interface",
    "iface", "address", "addr", "ip", "ip_address", "public_ip",
    "private_ip", "network_interface", "ingress", "egress",
    "allow", "permitted_cidr", "authorized_networks",
    "access_control", "white_list", "source_ranges", "expose",
    "published", "external", "net_bind", "bindip",
    "bindaddress", "listenaddress", "listenhost"
}

normalize_key(key_str) = trimmed {
    trimmed := trim(key_str, ":'\"")
}

is_unrestricted_ip(value) {
    unrestricted_ip_values[value]
}

name_matches_binding_keyword(name) {
    lower_name := lower(name)
    some kw in binding_related_keywords
    contains(lower_name, kw)
}

get_key_string(key_node) = s {
    key_node.ir_type in ["String", "VariableReference"]
    s := key_node.value
}

# Collect all hash entries recursively
collect_hash_entries(node) = entries {
    entries := {e |
        walk(node, [path, n])
        n.ir_type == "Hash"
        some item in n.value
        e := item
    }
}

# Collect all entries from nested hashes with their context
collect_all_hash_entries_with_context(root) = all_entries {
    all_entries := {entry |
        walk(root, [_, hash_node])
        hash_node.ir_type == "Hash"
        some item in hash_node.value
        key_str := get_key_string(item.key)
        norm_key := normalize_key(key_str)
        entry := {
            "key": norm_key,
            "key_node": item.key,
            "value": item.value,
            "hash_node": hash_node,
            "original_item": item
        }
    }
}

# Find String nodes with unrestricted values anywhere in the value tree
find_unrestricted_strings(node) = found {
    found := {s |
        walk(node, [_, n])
        n.ir_type == "String"
        is_unrestricted_ip(n.value)
        s := n
    }
}

# Check if any string in the node matches unrestricted IP
has_unrestricted_string(node) {
    some s in find_unrestricted_strings(node)
}

# Match bind-related key specifically
is_bind_related_key(key) {
    name_matches_binding_keyword(key)
} else {
    key == "ip"
} else {
    key == ":ip"
}

# Main detection: Variable with binding-related name and unrestricted value
Glitch_Analysis[result] {
    ub := glitch_lib._gather_parent_unit_blocks[_]
    ub.path != ""
    
    walk(ub, [_, node])
    node.ir_type == "Variable"
    
    name_matches_binding_keyword(node.name)
    
    some s in find_unrestricted_strings(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": ub.path,
        "description": description
    }
}

# Detection: Hash entry with binding-related key and unrestricted value  
Glitch_Analysis[result] {
    ub := glitch_lib._gather_parent_unit_blocks[_]
    ub.path != ""
    
    entries := collect_all_hash_entries_with_context(ub)
    entry := entries[_]
    
    is_bind_related_key(entry.key)
    
    some s in find_unrestricted_strings(entry.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": entry.original_item,
        "path": ub.path,
        "description": description
    }
}

# Detection: Attribute with binding-related name and unrestricted value
Glitch_Analysis[result] {
    ub := glitch_lib._gather_parent_unit_blocks[_]
    ub.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(ub)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    name_matches_binding_keyword(attr.name)
    some s in find_unrestricted_strings(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": ub.path,
        "description": description
    }
}

# Detection: Nested hash in attribute value with binding key and unrestricted value
Glitch_Analysis[result] {
    ub := glitch_lib._gather_parent_unit_blocks[_]
    ub.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(ub)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    entries := collect_all_hash_entries_with_context(attr.value)
    entry := entries[_]
    
    is_bind_related_key(entry.key)
    some s in find_unrestricted_strings(entry.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": ub.path,
        "description": description
    }
}