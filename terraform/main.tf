# Deploys CloudGuard as a scheduled, serverless scanner:
#   EventBridge (daily) -> Lambda (scan) -> S3 (reports) + SNS (email alerts)

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "me" {}

locals {
  name = "cloudguard"
  tags = { Project = "CloudGuard", ManagedBy = "Terraform" }
}

# ---------------------------------------------------------------- report bucket (private, encrypted, versioned)
resource "aws_s3_bucket" "reports" {
  bucket        = "${local.name}-reports-${data.aws_caller_identity.me.account_id}"
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    id     = "expire-old-reports"
    status = "Enabled"
    filter {}
    expiration { days = var.report_retention_days }
  }
}

# ---------------------------------------------------------------- alerts
resource "aws_sns_topic" "alerts" {
  name = "${local.name}-alerts"
  tags = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------- IAM (least privilege: read-only audit + write own bucket/topic)
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "outputs" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/reports/*"]
  }
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "outputs" {
  name   = "write-reports-and-alerts"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.outputs.json
}

# ---------------------------------------------------------------- Lambda
data "archive_file" "pkg" {
  type        = "zip"
  source_dir  = "${path.module}/../cloudguard"
  output_path = "${path.module}/build/cloudguard.zip"
  excludes    = ["__pycache__", "demo.py"]
}

resource "aws_lambda_function" "scanner" {
  function_name    = local.name
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "cloudguard.lambda_handler.handler"
  filename         = data.archive_file.pkg.output_path
  source_code_hash = data.archive_file.pkg.output_base64sha256
  timeout          = 300
  memory_size      = 256
  tags             = local.tags

  environment {
    variables = {
      REPORT_BUCKET   = aws_s3_bucket.reports.id
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
      SCAN_REGIONS    = join(",", var.scan_regions)
    }
  }
}

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/${aws_lambda_function.scanner.function_name}"
  retention_in_days = 30
  tags              = local.tags
}

# ---------------------------------------------------------------- schedule
resource "aws_cloudwatch_event_rule" "daily" {
  name                = "${local.name}-schedule"
  schedule_expression = var.schedule
  tags                = local.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.daily.name
  arn  = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily.arn
}
