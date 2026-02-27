package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_network_service(node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_binding_attr(attr.name)

    attr.value.ir_type == "String"
    (attr.value.value == "0.0.0.0" or attr.value.value == "0.0.0.0/0")

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to unrestricted IP address (0.0.0.0 or 0.0.0.0/0) - This exposes the service to all network interfaces, increasing attack surface and risk of DoS. (CWE-1327)"
    }
}

is_network_service(t) {
    t == "server" or
    t == "service" or
    t == "api" or
    t == "db" or
    t == "database" or
    t == "endpoint" or
    t == "listener" or
    t == "cloud_instance" or
    t == "vm" or
    t == "container" or
    t == "firewall" or
    t == "config" or
    t == "settings" or
    t == "module" or
    t == "recipe" or
    t == "task" or
    t == "hypervisor" or
    t == "vnc" or
    t == "tcp" or
    t == "udp" or
    t == "machine" or
    t == "instance" or
    t == "host"
}

is_binding_attr(name) {
    name == "listenaddr" or
    name == "bind_address" or
    name == "host" or
    name == "address" or
    name == "interface" or
    name == "ip" or
    name == "bind" or
    name == "network_host" or
    name == "bound_to" or
    name == "bind_to" or
    name == "local_only" or
    name == "private" or
    name == "internal" or
    name == "network" or
    name == "allow_all" or
    name == "public_access" or
    name == "expose_to_public" or
    name == "accessible_from_anywhere" or
    name == "external_access" or
    name == "wildcard_ip" or
    name == "source" or
    name == "bind_addr" or
    name == "vncserver_listen" or
    name == "listen" or
    name == "bind_ip" or
    name == "host_address" or
    name == "addr" or
    name == "listen_ip" or
    name == "exposed_to" or
    name == "server_address" or
    name == "service_host" or
    name == "bind_host" or
    name == "network_interface" or
    name == "network_bind" or
    name == "listen_interface" or
    name == "bind_interface" or
    name == "address_bind" or
    name == "listen_address" or
    name == "addr_bind" or
    name == "host_bind" or
    name == "binding" or
    name == "listen_on" or
    name == "host_bind" or
    name == "bind_address" or
    name == "bind_host" or
    name == "bind_interface" or
    name == "host_bind_address"