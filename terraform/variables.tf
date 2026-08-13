variable "ovh_auth_url" {
  description = "OVH OpenStack auth endpoint (region-specific, e.g. https://auth.cloud.ovh.net/v3)"
  type        = string
}

variable "ovh_project_id" {
  description = "OVH Public Cloud project ID"
  type        = string
}

variable "ovh_username" {
  description = "OVH OpenStack user (from OVH Public Cloud > Users & Roles)"
  type        = string
  sensitive   = true
}

variable "ovh_password" {
  description = "OVH OpenStack user password"
  type        = string
  sensitive   = true
}

variable "ovh_region" {
  description = "OVH region, e.g. GRA7, SBG5, DE1"
  type        = string
  default     = "GRA7"
}

variable "instance_flavor" {
  description = "VPS size/flavor"
  type        = string
  default     = "b2-15" # 4 vCPU / 15GB RAM
}

variable "ssh_keypair_name" {
  description = "Name of SSH keypair already uploaded to OVH"
  type        = string
}

variable "external_network_name" {
  description = "OVH's public/external network pool name"
  type        = string
  default     = "Ext-Net"
}