output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "public_bucket" {
  value = aws_s3_bucket.public_data.bucket
}

output "public_object_url" {
  description = "Anyone on the internet can fetch this (fake data)"
  value       = "https://${aws_s3_bucket.public_data.bucket}.s3.${var.region}.amazonaws.com/fake-passwords.txt"
}

output "users" {
  value = [aws_iam_user.dev_admin.name, aws_iam_user.dev_wildcard.name]
}

output "roles" {
  value = [aws_iam_role.ec2_admin.name, aws_iam_role.open_trust.name]
}
