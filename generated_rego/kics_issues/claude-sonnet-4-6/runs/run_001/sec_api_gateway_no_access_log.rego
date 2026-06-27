package glitch

import data.glitch_lib

stage_in_deployment(node) {
    contains(node.type, "deployment")
    regex.match("(?i)stage_name", node.code)
}

missing_access_log(node) {
    not regex.match("(?i)access_log_settings", node.code)
}

missing_destination_arn(node) {
    regex.match("(?i)access_log_settings", node.code)
    not regex.match(`(?i)destination_arn\s*=\s*"[^"]+"`, node.code)
    not regex.match(`(?i)destination_arn\s*=\s*[a-zA-Z][a-zA-Z0-9_.]*`, node.code)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    stage_in_deployment(node)
    missing_access_log(node)

    result := {
        "type": "sec_api_gateway_no_access_log",
        "element": node,
        "path": parent.path,
        "description": "Missing Access Log Settings in API Gateway Stage - API Gateway Stage linked to a deployment must have access logging configured with a valid destination. (CWE-778)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    stage_in_deployment(node)
    missing_destination_arn(node)

    result := {
        "type": "sec_api_gateway_no_access_log",
        "element": node,
        "path": parent.path,
        "description": "Missing Access Log Settings in API Gateway Stage - API Gateway Stage linked to a deployment must have access logging configured with a valid destination. (CWE-778)"
    }
}