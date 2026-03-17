package glitch

import data.glitch_lib

binding_attr_names := {
    "listen_address", "listenaddr", "listen_on", "listen", "listen_host",
    "bind_address", "bind_addr", "bindaddress", "bind", "bind_host",
    "host", "hostname", "server_address", "address", "ip", "ip_address",
    "interface", "network_interface", "iface",
    "allowed_hosts", "allowed_ips", "allowed_ip_ranges",
    "public_ip", "public_address", "public_endpoint", "endpoint",
    "accept_address", "connect_address", "source_address",
    "source", "vncserver_listen", "listen_ip", "management_ip"
}

wildcard_ips := {"0.0.0.0", "::", "0:0:0:0:0:0:0:0", "0.0.0.0/0", "::/0", "*", "INADDR_ANY", ""}

is_wildcard_string(value) {
    value.ir_type == "String"
    value.value == wildcard_ips[_]
}

is_binding_attr(name) {
    lower(name) == binding_attr_names[_]
}

# Rule 1: Wildcard IP in atomic unit attributes (Puppet, Terraform, Ansible task-level attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_binding_attr(attr.name)
    is_wildcard_string(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is configured to bind to a wildcard IP address, exposing it on all network interfaces. (CWE-1327)"
    }
}

# Rule 2: Wildcard IP in hash entries within unit blocks (Chef variables, Ansible dictionary attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, entry])
    entry.key.ir_type == "String"
    is_binding_attr(entry.key.value)
    is_wildcard_string(entry.value)

    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Configuration contains a wildcard IP binding in a hash entry. (CWE-1327)"
    }
}

# Rule 3: publicly_accessible = true
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "publicly_accessible"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Resource is marked as publicly accessible, exposing it to all networks without interface restriction. (CWE-1327)"
    }
}

# Rule 4: public_network_access_enabled = true
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "public_network_access_enabled"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Public network access is enabled for this resource, potentially exposing it on all interfaces. (CWE-1327)"
    }
}

# Rule 5: cidr_blocks containing 0.0.0.0/0
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "cidr_blocks"
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    item.value == "0.0.0.0/0"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Network rule allows unrestricted inbound access from all IPv4 addresses (0.0.0.0/0). (CWE-1327)"
    }
}

# Rule 6: ipv6_cidr_blocks containing ::/0
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "ipv6_cidr_blocks"
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    item.value == "::/0"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Network rule allows unrestricted inbound access from all IPv6 addresses (::/0). (CWE-1327)"
    }
}

# Rule 7: hostNetwork = true (Kubernetes container networking)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "hostnetwork"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Container is configured with hostNetwork:true, binding services to all host network interfaces. (CWE-1327)"
    }
}