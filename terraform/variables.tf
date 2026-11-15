variable "region" {
  description = "Region to deploy CloudGuard into"
  type        = string
  default     = "us-east-1"
}

variable "scan_regions" {
  description = "Regions the scanner audits"
  type        = list(string)
  default     = ["us-east-1"]
}

variable "schedule" {
  description = "EventBridge schedule expression"
  type        = string
  default     = "rate(1 day)"
}

variable "alert_email" {
  description = "Email for CRITICAL/HIGH alerts (confirm the SNS subscription email). Leave empty to skip."
  type        = string
  default     = ""
}

variable "report_retention_days" {
  description = "Days to keep reports in S3"
  type        = number
  default     = 90
}
