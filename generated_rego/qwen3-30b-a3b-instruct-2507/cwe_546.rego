package glitch

import data.glitch_lib

suspect_keywords := {
    "TODO",
    "FIXME",
    "HACK",
    "LATER",
    "WIP",
    "CAPTURE",
    "NOT IMPLEMENTED",
    "NA",
    "WORKAROUND",
    "Note:"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comments := parent.comments[_]
    comment_content := comments.content

    keyword := suspect_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), comment_content)

    is_security_critical := any_of_security_resources[parent.type]
    is_within_security_context := any_of_security_contexts[parent.path]

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    in_security_resource := any_of_security_resources[node.type]
    in_security_context := any_of_security_contexts[parent.path]

    if is_security_critical or is_within_security_context {
        if in_security_resource or in_security_context {
            result := {
                "type": "sec_susp_comm",
                "element": comments,
                "path": parent.path,
                "description": sprintf("Suspicious comment found: %s. Indicates incomplete or insecure logic, possibly related to security controls. (CWE-546)", [comment_content])
            }
        }
    }
}

any_of_security_resources := {
    "aws_s3_bucket",
    "aws_security_group",
    "aws_lb_listener",
    "aws_iam_role",
    "aws_rds_instance",
    "aws_cloudformation_stack",
    "pulumi.Config",
    "aws_dynamodb_table",
    "aws_eks_cluster",
    "aws_lambda_function",
    "aws_vpc",
    "aws_internet_gateway",
    "aws_route_table",
    "aws_subnetwork",
    "aws_network_acl",
    "aws_kms_key",
    "aws_sqs_queue",
    "aws_sns_topic",
    "aws_iam_policy",
    "aws_iam_user",
    "aws_iam_group",
    "aws_iam_instance_profile",
    "aws_codepipeline",
    "aws_codebuild_project",
    "aws_cognito_user_pool"
}

any_of_security_contexts := {
    "/security/",
    "/iam/",
    "/network/",
    "/vpc/",
    "/firewall/",
    "/audit/",
    "/logging/",
    "/encryption/",
    "/compliance/",
    "/policies/",
    "/rules/",
    "/template/",
    "security.tf",
    "network.tf",
    "iam.tf",
    "policy.tf",
    "infra.tf"
}