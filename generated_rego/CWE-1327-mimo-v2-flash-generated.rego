package glitch

import data.glitch_lib

# Define the regex pattern for unrestricted IP addresses and words
unrestricted_regex = "^(?i)(0\\.0\\.0\\.0|::|0\\.0\\.0\\.0/0|::/0|all|any|\\*)$"
network_service_regex = "(?i)(server|service|listener|container|pod|database|endpoint|route|gateway|ingress|mysql|postgres|nginx|apache|redis|mongodb|kafka|zookeeper)"

# Binding attribute names to check (case-insensitive)
binding_attrs = {"listen_address", "bind_address", "host", "ip_address", "server_address", "listenaddr", "address", "host_ip"}

# Port attribute names to check (case-insensitive)
port_attrs = {"container_port", "expose_port", "port", "published_port"}

# Check for unrestricted binding in service configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check if the atomic unit represents a network service
    regex.match(network_service_regex, node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Normalize attribute name to lowercase for case-insensitive matching
    attr_name_lower := lower(attr.name)
    
    # Check if the attribute name matches one of the binding attributes
    # Use iteration over binding_attrs set for membership check
    binding_attr := binding_attrs[_]
    attr_name_lower == lower(binding_attr)

    # Check if the value is an unrestricted IP pattern
    attr.value.ir_type == "String"
    regex.match(unrestricted_regex, attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is configured to listen on all network interfaces (0.0.0.0, ::, etc.) instead of a specific IP, potentially exposing it publicly. (CWE-1327)"
    }
}

# Check for missing bind address in container resources (implicit unrestricted)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Focus on container and pod resources
    regex.match(network_service_regex, node.type)
    not contains(lower(node.type), "listener")  # Exclude listeners which might be covered by first rule

    attrs := glitch_lib.all_attributes(node)
    attr_names := {attr.name | attr := attrs[_]}
    
    # Convert all attribute names to lowercase
    attr_names_lower = {lower(x) | x := attr_names}

    # Check for port exposure attributes without host_ip restriction
    port_attr := port_attrs[_]
    attr_name := attr_names_lower[_]
    lower(port_attr) == attr_name

    # Check for absence of host_ip/host binding attributes
    # Define a local rule for existence of a binding attribute in the set
    exists_binding_attr = false
    exists_binding_attr {
        ba := binding_attrs[_]
        attr_name := attr_names_lower[_]
        lower(ba) == attr_name
    }

    # Then use the negation of that rule
    not exists_binding_attr

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Missing Binding Address in Container Resource - The container/pod configuration exposes ports without specifying a host IP restriction, defaulting to all interfaces (0.0.0.0). (CWE-1327)"
    }
}

# Check for network_mode that allows unrestricted access
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for network_mode attributes with unsafe values
    attr_name_lower := lower(attr.name)
    attr_name_lower == "network_mode"

    attr.value.ir_type == "String"
    regex.match("(?i)(host|bridge)", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unsafe Network Mode Configuration - Using 'host' or 'bridge' network mode without restrictions can expose services to all network interfaces. (CWE-1327)"
    }
}