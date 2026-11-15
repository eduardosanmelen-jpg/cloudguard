output "report_bucket" {
  value = aws_s3_bucket.reports.id
}

output "lambda_function" {
  value = aws_lambda_function.scanner.function_name
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "run_now" {
  description = "Trigger a scan immediately"
  value       = "aws lambda invoke --function-name ${aws_lambda_function.scanner.function_name} out.json && cat out.json"
}
