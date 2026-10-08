###############################################################################
# VULNERABLE LAB - every weakness below is INTENTIONAL.
# Use only in your own throwaway AWS account. Fake data only.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.5" }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  prefix = "${var.project}-${random_id.suffix.hex}"
  tags   = { Project = var.project, Intentional = "vulnerable-lab" }
}

# -----------------------------------------------------------------------------
# S3 MISCONFIG 1: publicly readable + listable bucket
# (Block Public Access disabled, bucket policy grants Principal "*")
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "public_data" {
  bucket        = "${local.prefix}-public-data"
  force_destroy = true
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket                  = aws_s3_bucket.public_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_data" {
  bucket     = aws_s3_bucket.public_data.id
  depends_on = [aws_s3_bucket_public_access_block.public_data]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject"]
        Resource  = "${aws_s3_bucket.public_data.arn}/*"
      },
      {
        Sid       = "PublicList"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:ListBucket"]
        Resource  = aws_s3_bucket.public_data.arn
      }
    ]
  })
}

resource "aws_s3_object" "fake_secrets" {
  bucket       = aws_s3_bucket.public_data.id
  key          = "fake-passwords.txt"
  content_type = "text/plain"
  content      = "FAKE DATA - LAB ONLY\nadmin:Passw0rd-not-real\ndb_user:hunter2-not-real\n"
  depends_on   = [aws_s3_bucket_policy.public_data]
}

# -----------------------------------------------------------------------------
# S3 MISCONFIG 2: "backups" bucket with no versioning and no access logging
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "backups" {
  bucket        = "${local.prefix}-backups"
  force_destroy = true
  tags          = local.tags
}

# -----------------------------------------------------------------------------
# IAM MISCONFIG 1: user with full AdministratorAccess, attached directly
# -----------------------------------------------------------------------------
resource "aws_iam_user" "dev_admin" {
  name = "${local.prefix}-dev-admin"
  tags = local.tags
}

resource "aws_iam_user_policy_attachment" "dev_admin" {
  user       = aws_iam_user.dev_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# -----------------------------------------------------------------------------
# IAM MISCONFIG 2: "developer" with service-wide wildcards and
# privilege-escalation permissions on Resource "*"
# -----------------------------------------------------------------------------
resource "aws_iam_user" "dev_wildcard" {
  name = "${local.prefix}-dev-wildcard"
  tags = local.tags
}

resource "aws_iam_user_policy" "dev_wildcard" {
  name = "developer-everything"
  user = aws_iam_user.dev_wildcard.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*", "ec2:*"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole",
          "iam:AttachUserPolicy",
          "iam:CreatePolicyVersion",
          "iam:CreateAccessKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# IAM MISCONFIG 3: role trusted by EC2 with AdministratorAccess
# (any instance profile using it = full account takeover if the host is popped)
# -----------------------------------------------------------------------------
resource "aws_iam_role" "ec2_admin" {
  name = "${local.prefix}-ec2-admin-role"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_admin" {
  role       = aws_iam_role.ec2_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# -----------------------------------------------------------------------------
# IAM MISCONFIG 4: role whose TRUST policy lets ANY AWS principal assume it.
# SAFETY: this role has NO permissions attached. Never attach any.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "open_trust" {
  name = "${local.prefix}-open-trust-role"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# -----------------------------------------------------------------------------
# IAM MISCONFIG 5: weak account password policy
# -----------------------------------------------------------------------------
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6
  require_lowercase_characters   = false
  require_uppercase_characters   = false
  require_numbers                = false
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0
  password_reuse_prevention      = 0
}

# -----------------------------------------------------------------------------
# Free detective control: IAM Access Analyzer (external access findings)
# -----------------------------------------------------------------------------
resource "aws_accessanalyzer_analyzer" "lab" {
  analyzer_name = "${local.prefix}-analyzer"
  type          = "ACCOUNT"
}
