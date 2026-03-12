package glitch

import data.glitch_lib

insecure_protocols = {"http", "ftp", "smtp", "telnet", "pop3", "imap"}
insecure_ports = {80, 21, 25, 110, 143, 8080}
url_attributes = {"url", "endpoint", "connection_string", "base_url", "api_endpoint", "backend_url", "service_url", "uri", "link", "address", "host", "server", "source", "src", "proxypass"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "protocol"
    attr.value.ir_type == "String"
    insecure_protocols[x]
    attr.value.value == x

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Use of unencrypted protocol in transmission configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "String"
    url_attributes[attr_name]
    walk(node, [path2, attr])
    attr.ir_type == "Attribute"
    attr.name == attr_name
    check_string_in_parent(n, attr.value)
    insecure_url(n.value)

    result := {
        "type": "sec_https",
        "element": n,
        "path": parent.path,
        "description": "URL uses unencrypted protocol (HTTP). (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "enable_ssl"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "SSL is disabled in transmission configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "use_tls"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "TLS is disabled in transmission configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "https_only"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "HTTPS only is disabled in transmission configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "require_ssl"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "SSL is not required in transmission configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "secure_transfer"
    attr.value.ir_type == "String"
    attr.value.value == "disabled"

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Secure transfer is disabled in transmission configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "allow_insecure_connections"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure connections are allowed in transmission configuration. (CWE-319)"
    }
}

check_string_in_parent(string_node, parent_value) {
    walk(parent_value, [path, node])
    node == string_node
}

insecure_url(str) {
    insecure_protocols[x]
    regex.match(sprintf("%s://", [x]), str)
}