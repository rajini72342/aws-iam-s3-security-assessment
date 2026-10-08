variable "region" {
  description = "AWS region for the lab"
  type        = string
  default     = "ap-south-1"
}

variable "project" {
  description = "Name prefix for all lab resources"
  type        = string
  default     = "iamlab"
}
