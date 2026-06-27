package glitch

import data.glitch_lib

# Core suspicious keywords - indication of incomplete/insecure code
suspicious_keywords := {
    "security", "insecure", "vulnerable", "bypass", "workaround", "temporary",
    "todo", "fixme", "xxx", "hack", "bug", "broken", "incomplete",
    "later", "later2", "future", "remove", "cleanup", "refactor",
    "warning", "danger", "caution", "note", "attention",
    "deprecated", "obsolete", "deprecate", "breaking"
}

# Check if comment contains suspicious keyword
contains_suspicious_keyword(content) {
    lowered := lower(content)
    kw := suspicious_keywords[_]
    regex.match(sprintf(".*\\b%s\\b.*", [kw]), lowered)
}

# Detect URLs to issue trackers indicating known problems
contains_issue_url(content) {
    regex.match(`https?://.*/issues/\d+`, content)
} else {
    regex.match(`https?://.*/(bug|issue|tracker)/\d+`, lower(content))
}

# Detect deprecation marker specifically - must contain "deprecated" word
contains_deprecation_marker(content) {
    regex.match(`deprecated\s+in\s+\d+\.\d+\+`, lower(content))
} else {
    regex.match(`\bdeprecated\b`, lower(content))
}

# Detect construction/destruction keywords indicating problems - must be explicit
contains_construction_problem(content) {
    regex.match(`\b(break|breaks|broken)\s+(the\s+)?(cookbook|code|deployment|build|script|system|infrastructure)\b`, lower(content))
}

# Collect all comments from anywhere in the IR structure
all_comments(node) = comments {
    comments = {c |
        walk(node, [_, c])
        c.ir_type == "Comment"
    }
}

# Check if comment is suspicious (contains keyword, issue URL, or deprecation marker)
is_suspicious_comment(comment) {
    contains_suspicious_keyword(comment.content)
} else {
    contains_issue_url(comment.content)
} else {
    contains_deprecation_marker(comment.content)
} else {
    contains_construction_problem(comment.content)
}

# Check if comment is just a version marker without suspicious content (false positive pattern)
is_just_version_marker(content) {
    trimmed := trim(content, " ")
    regex.match(`^(default\s+\d+(\s+\w+)?\s+)?in\s+\d+\.\d+[\.,]\d*\+?$`, lower(trimmed))
} else {
    regex.match(`^\d+(\.\d+)+[\+,]?$`, trim(content, " "))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Collect all comments from this UnitBlock and nested structures
    comments := all_comments(parent)
    comment := comments[_]
    
    # Check if comment is suspicious
    is_suspicious_comment(comment)
    
    # Filter out version-only markers that aren't actually suspicious
    not is_just_version_marker(comment.content)
    
    # Filter out very short comments that don't provide meaningful context
    count(trim(comment.content, " ")) > 5
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment indicating security gap, incomplete work, deprecated feature, or known issue. (CWE-546)"
    }
}