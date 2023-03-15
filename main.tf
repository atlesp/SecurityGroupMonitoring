terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }

  required_version = ">= 0.14.9"
}

provider "aws" {
  region = "eu-west-1"
}

data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name               = "assignment-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "basic" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_role.name
}


# the lambda
data "archive_file" "python_lambda_package" {
  type        = "zip"
  source_file = "${path.module}/code/security_group_check.py"
  output_path = "security_group_check.zip"
}

resource "aws_lambda_function" "security_check" {
  function_name    = "Assignment-SecurityGroupCheck"
  filename         = "security_group_check.zip"
  source_code_hash = data.archive_file.python_lambda_package.output_base64sha256
  role             = aws_iam_role.lambda_role.arn
  runtime          = "python3.9"
  handler          = "security_group_check.lambda_handler"
  timeout          = 10
  environment {
    variables = {
      SNS_TOPIC = "${aws_sns_topic.topic.arn}"
    }
  }
}

# Cloudwatch log group
resource "aws_cloudwatch_log_group" "function_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.security_check.function_name}"
  retention_in_days = 7
  lifecycle {
    prevent_destroy = false
  }
}



# Notification SNS topic 
resource "aws_sns_topic" "topic" {
  name = "assignment-security-check"
}

# sends the notification to my email for testing 
resource "aws_sns_topic_subscription" "email-target" {
  topic_arn = aws_sns_topic.topic.arn
  protocol  = "email"
  endpoint  = "atle@esperum.no"
}

resource "aws_iam_role_policy" "custom_policy" {
  name = "assignment_custom_policy"
  role = aws_iam_role.lambda_role.name
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "SNS:Publish*",
        ]
        Effect   = "Allow"
        Resource = "${aws_sns_topic.topic.arn}"
      },
      {
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeNetworkInterfaces"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
 
    ]
  })
}

# AuthorizeSecurityGroupIngress
# Trigger lambda on security group ingress changes.
# This is also triggered on security group creation
resource "aws_cloudwatch_event_rule" "ingress_rule_added" {
  name        = "assignment-capture-new-ingress-rule-added"
  description = "Capture when new ingress rule are added to a security group"

  event_pattern = jsonencode({
    "detail-type" : [
      "AWS API Call via CloudTrail"
    ],
    "detail" : {
      "eventSource" : [
        "ec2.amazonaws.com"
      ],
      "eventName" : [
        "AuthorizeSecurityGroupIngress"
      ]
    }
  })

}

# allow event rule to trigger lambda
resource "aws_lambda_permission" "trigger_lambda_from_event" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_check.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ingress_rule_added.arn
}

# make the event rule trigger the lambda when it occurs
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.ingress_rule_added.name
  target_id = "NewIngressRuleToLambda"
  arn       = aws_lambda_function.security_check.arn
}


# ModifyNetworkInterfaceAttribute
# Trigger lambda on security group ingress changes.
# This is also triggered on security group creation
resource "aws_cloudwatch_event_rule" "interface_modified" {
  name        = "assignment-capture-interface-modified"
  description = "Capture when a newtwork interface is changes"

  event_pattern = jsonencode({
    "detail-type" : [
      "AWS API Call via CloudTrail"
    ],
    "detail" : {
      "eventSource" : [
        "ec2.amazonaws.com"
      ],
      "eventName" : [
        "ModifyNetworkInterfaceAttribute"
      ]
    }
  })

}

# allow event rule to trigger lambda
resource "aws_lambda_permission" "trigger_lambda_from_modified_event" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_check.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.interface_modified.arn
}

# make the event rule trigger the lambda when it occurs
resource "aws_cloudwatch_event_target" "modified_lambda" {
  rule      = aws_cloudwatch_event_rule.interface_modified.name
  target_id = "NetorkInterfaceModfiedRuleToLambda"
  arn       = aws_lambda_function.security_check.arn
}


# RunInstances
# Trigger lambda on security group ingress changes.
# This is also triggered on security group creation
resource "aws_cloudwatch_event_rule" "run_instance" {
  name        = "assignment-capture-runinstance"
  description = "Capture when a new instance starts to run"

  event_pattern = jsonencode({
    "detail-type" : [
      "AWS API Call via CloudTrail"
    ],
    "detail" : {
      "eventSource" : [
        "ec2.amazonaws.com"
      ],
      "eventName" : [
        "RunInstances"
      ]
    }
  })

}

# allow event rule to trigger lambda
resource "aws_lambda_permission" "trigger_lambda_from_runinstance_event" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_check.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.run_instance.arn
}

# make the event rule trigger the lambda when it occurs
resource "aws_cloudwatch_event_target" "runinstance_lambda" {
  rule      = aws_cloudwatch_event_rule.run_instance.name
  target_id = "NetorkInterfaceModfiedRuleToLambda"
  arn       = aws_lambda_function.security_check.arn
}


