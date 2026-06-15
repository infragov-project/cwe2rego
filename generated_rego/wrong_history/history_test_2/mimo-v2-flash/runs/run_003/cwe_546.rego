package glitch

import data.glitch_lib

# Define the suspicious keywords for CWE-546
suspicious_keywords := {"TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "XXX", "NOTE"}

# Check if a comment content contains any of the suspicious keywords (case-insensitive)
contains_suspicious_keyword(comment_content) {
    keyword := suspicious_keywords[_]
    regex.match(sprintf("(?i).*\\b%s\\b", [keyword]), comment_content)
}

# Rule 1: Detect suspicious keywords in comments (Direct Comment Detection)
Glitch_Analysis[result] {
    # Gather all unit blocks (scripts, tasks, vars, etc.)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check comments in the unit block
    comment := parent.comments[_]
    contains_suspicious_keyword(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment marker indicating incomplete implementation or bypassed security checks (CWE-546)"
    }
}

# Rule 2: Detect suspicious keywords in string values of attributes/variables (Implicit Weakness via String Attributes)
Glitch_Analysis[result] {
    # Gather all unit blocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check attributes in the unit block
    attr := glitch_lib.all_attributes(parent)[_]
    attr.value.ir_type == "String"
    contains_suspicious_keyword(attr.value.value)

    result := {
        "type": "sec_susp_comm",
        "element": attr,
        "path": parent.path,
        "description": "Suspicious keyword in attribute value indicating incomplete implementation (CWE-546)"
    }
}

# Rule 3: Detect suspicious keywords in variable values (Implicit Weakness via String Attributes)
Glitch_Analysis[result] {
    # Gather all unit blocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check variables in the unit block
    var := glitch_lib.all_variables(parent)[_]
    var.value.ir_type == "String"
    contains_suspicious_keyword(var.value.value)

    result := {
        "type": "sec_susp_comm",
        "element": var,
        "path": parent.path,
        "description": "Suspicious keyword in variable value indicating incomplete implementation (CWE-546)"
    }
}

# Rule 4: Detect suspicious keywords in atomic unit attributes (e.g., resource names or descriptions)
Glitch_Analysis[result] {
    # Gather all unit blocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Check atomic units
    atomic_unit := glitch_lib.all_atomic_units(parent)[_]
    attrs := glitch_lib.all_attributes(atomic_unit)
    attr := attrs[_]
    attr.value.ir_type == "String"
    contains_suspicious_keyword(attr.value.value)

    result := {
        "type": "sec_susp_comm",
        "element": attr,
        "path": parent.path,
        "description": "Suspicious keyword in atomic unit attribute value indicating incomplete implementation (CWE-546)"
    }
}