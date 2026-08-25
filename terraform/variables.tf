variable "contabo_client_id" {
  description = "Contabo OAuth2 client ID (Customer Control Panel > Account > API)"
  type        = string
  sensitive   = true
}

variable "contabo_client_secret" {
  description = "Contabo OAuth2 client secret"
  type        = string
  sensitive   = true
}

variable "contabo_user" {
  description = "Contabo account email/username"
  type        = string
  sensitive   = true
}

variable "contabo_password" {
  description = "Contabo account password"
  type        = string
  sensitive   = true
}

variable "contabo_region" {
  description = "Contabo data center region"
  type        = string
  default     = "EU" # Contabo's European region pool
}

variable "instance_display_name" {
  description = "Human-readable name shown in the Contabo control panel"
  type        = string
  default     = "soc-platform-vps"
}

variable "instance_product_id" {
  description = "Contabo product/plan ID for the VPS size (see Contabo product API for current IDs)"
  type        = string
  default     = "V45" # ~4 vCPU / 8GB RAM tier, matching the deployed instance
}

variable "instance_image_id" {
  description = "Contabo OS image ID to boot from"
  type        = string
  default     = "afecbb85-e2fc-46f0-9684-b46b1faf00bb" # Ubuntu 22.04 LTS (Contabo image catalog)
}

variable "ssh_key_ids" {
  description = "List of Contabo secret IDs for SSH public keys to inject into the instance"
  type        = list(number)
  default     = []
}