package glitch

import data.glitch_lib

# Network binding indicators that suggest IP binding configuration
network_indicators := {"bind", "bindip", "bind_ip", "bindaddress", "bind_address", "host", "listen", "ip", "address", "addr", "interface"}

# Unrestricted network values indicating exposure to all interfaces
unrestricted_networks := {"0.0.0.0", "0.0.0.0/0", "::", "::/0", "*", "any", "all", "0.0.0.0/32", "[::]", "0:0:0:0:0:0:0:0"}

# String patterns that indicate actual resource instantiation (not just data)
resource_action_indicators := {"template", "service", "file", "package", "execute", "command", "script", "cron", "mount", "user", "group", "directory", "link", "route", "firewall", "selinux", "sysctl", "kernel_module", "sysctl_param", "minecraft_server", "windows_feature", "registry_key", "env", "path", "include_recipe", "notifies", "subscribes", "only_if", "unless"}

# Check if string indicates network binding context
is_network_context(str) {
    lower_str := lower(str)
    indicator := network_indicators[_]
    contains(lower_str, indicator)
}

# Check if value represents unrestricted network access
is_unrestricted_network(val) {
    val.ir_type == "String"
    clean_val := replace(replace(lower(val.value), "'", ""), "\"", "")
    clean_val == unrestricted_networks[_]
}

# Strip Ruby symbol prefix for Chef
strip_symbol(s) = result {
    startswith(s, ":")
    result := substring(s, 1, -1)
} else = s

# Convert various key types to string
to_string(x) = s {
    x.ir_type == "String"
    s := x.value
} else = s {
    x.ir_type == "VariableReference"
    s := x.value
} else = "" {
    true
}

# Check if a node has ancestors that indicate actual resource usage (not just data definition)
has_resource_context(node, parent) {
    walk(parent, [path, ancestor])
    ancestor != node
    ancestor.ir_type == "AtomicUnit"
    contains(lower(ancestor.type), resource_action_indicators[_])
} else {
    walk(parent, [path, ancestor])
    ancestor != node
    ancestor.ir_type == "MethodCall"
    contains(lower(ancestor.method), resource_action_indicators[_])
} else {
    walk(parent, [path, ancestor])
    ancestor != node
    ancestor.ir_type == "FunctionCall"
    contains(lower(ancestor.name), resource_action_indicators[_])
}

# Check if variable is used in a resource context by examining sibling statements
used_in_resource_context(parent, var_name) {
    walk(parent, [_, stmt])
    stmt.ir_type == "AtomicUnit"
    contains(lower(stmt.type), resource_action_indicators[_])
    walk(stmt, [_, used])
    used.ir_type == "VariableReference"
    used.value == var_name
}

# Check if a Hash contains resource-related keys that indicate active configuration
has_resource_keys(hash_node) {
    hash_node.ir_type == "Hash"
    some i
    pair := hash_node.value[i]
    kval := to_string(pair.key)
    kclean := strip_symbol(kval)
    contains(lower(kclean), resource_action_indicators[_])
}

# Check if Hash is directly assigned to a resource attribute
is_resource_attribute_value(node, parent) {
    walk(parent, [_, ancestor])
    ancestor.ir_type == "Attribute"
    ancestor.value == node
    walk(parent, [_, au])
    au.ir_type == "AtomicUnit"
    contains(lower(au.type), resource_action_indicators[_])
}

# Check if this is just a data hash without resource context
is_data_hash_without_context(node, parent) {
    node.value.ir_type == "Hash"
    not has_resource_keys(node.value)
    not used_in_resource_context(parent, node.name)
}

# Main detection: Variables with network binding names and unrestricted values - only if used in resource context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    
    # Skip if just a data hash without resource context
    not is_data_hash_without_context(node, parent)
    
    # Check variable name indicates network binding
    is_network_context(node.name)
    
    # Check for unrestricted network in value
    is_unrestricted_network(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to unrestricted IP address (0.0.0.0), allowing access from any network. (CWE-284)"
    }
}

# Detection: Hash entries with network binding keys and unrestricted values in resource context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Look for Hash nodes that are in resource context
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    # Must have resource context - either part of atomic unit or has resource keys
    has_resource_context(node, parent)
    
    some i
    pair := node.value[i]
    k := pair.key
    v := pair.value
    
    kval := to_string(k)
    kclean := strip_symbol(kval)
    is_network_context(kclean)
    is_unrestricted_network(v)
    
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration contains unrestricted IP binding (0.0.0.0) in nested options. (CWE-284)"
    }
}

# Detection: Hash entries in resource attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    
    some i
    pair := attr.value.value[i]
    k := pair.key
    v := pair.value
    
    kval := to_string(k)
    kclean := strip_symbol(kval)
    is_network_context(kclean)
    is_unrestricted_network(v)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration contains unrestricted IP binding (0.0.0.0) in nested attribute options. (CWE-284)"
    }
}

# Detection: Attributes in atomic units with direct unrestricted values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_network_context(attr.name)
    is_unrestricted_network(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to unrestricted IP address (0.0.0.0), allowing access from any network. (CWE-284)"
    }
}

# Detection: Array values in attributes with unrestricted network
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_network_context(attr.name)
    attr.value.ir_type == "Array"
    
    some i
    is_unrestricted_network(attr.value.value[i])
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to unrestricted IP address (0.0.0.0) in array attribute. (CWE-284)"
    }
}