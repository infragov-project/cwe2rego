package glitch

import data.glitch_lib

# Core suspicious markers - standalone words indicating incomplete work
core_markers := {"TODO", "FIXME", "HACK", "XXX", "BUG"}

# Security-sensitive markers
security_markers := {"INSECURE", "VULNERABLE", "BYPASS", "SKIP_VALIDATION", "DISABLE_VERIFY", "DEBUG_MODE", "NOT_FOR_PROD", "HOTFIX", "WORKAROUND"}

# Technical debt and fragility markers
debt_markers := {"TEMPORARY", "PLACEHOLDER", "HARDCODED", "DEPRECATED", "OBSOLETE", "KLUDGE", "REFACTOR", "REWRITE"}

# Issue tracker indicators in URLs or references
tracker_indicators := {"github.com", "gitlab.com", "issues", "tracker", "jira", "bugzilla", "tickets"}

# Fragility/breakage language indicating known limitations
fragility_patterns := [
    "break the",
    "will break",
    "cannot change",
    "unable to change",
    "hard to change",
    "do not modify",
    "don't modify",
    "known issue",
    "known bug",
    "limited functionality",
    "not fully implemented",
    "partial implementation"
]

# Check for core marker at word boundary
has_core_marker(content) {
    marker := core_markers[_]
    regex.match(sprintf("(?i)\\b%s\\b", [marker]), content)
}

# Check for security marker at word boundary
has_security_marker(content) {
    marker := security_markers[_]
    regex.match(sprintf("(?i)\\b%s\\b", [marker]), content)
}

# Check for debt marker at word boundary
has_debt_marker(content) {
    marker := debt_markers[_]
    regex.match(sprintf("(?i)\\b%s\\b", [marker]), content)
}

# Check for issue tracker references (URLs or mentions)
has_tracker_reference(content) {
    indicator := tracker_indicators[_]
    regex.match(sprintf("(?i)%s", [indicator]), content)
}

# Check for fragility/breakage language
has_fragility_language(content) {
    pattern := fragility_patterns[_]
    regex.match(sprintf("(?i)%s", [pattern]), content)
}

# Collect all comments from unit block
all_comments(block) = comments {
    comments := {c | c := block.comments[_]}
}

# Main detection for core suspicious markers
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := all_comments(parent)[_]
    content := comment.content
    
    has_core_marker(content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment containing TODO, FIXME, HACK, XXX, or BUG marker indicating incomplete implementation or known issue. (CWE-546)"
    }
}

# Detection for security-related markers
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := all_comments(parent)[_]
    content := comment.content
    
    has_security_marker(content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Comment indicates security bypass, debug mode, or production-insecure configuration. (CWE-546)"
    }
}

# Detection for technical debt markers
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := all_comments(parent)[_]
    content := comment.content
    
    has_debt_marker(content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Comment indicates deprecated, hardcoded, or temporary implementation that may compromise infrastructure. (CWE-546)"
    }
}

# Detection for issue tracker references (indicates known documented issues)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := all_comments(parent)[_]
    content := comment.content
    
    has_tracker_reference(content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Reference to issue tracker URL indicates known problem or incomplete implementation requiring external documentation. (CWE-546)"
    }
}

# Detection for fragility/breakage language (indicates design constraints and technical debt)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := all_comments(parent)[_]
    content := comment.content
    
    has_fragility_language(content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Comment indicates fragile implementation with known limitations or constraints that could cause breakage. (CWE-546)"
    }
}