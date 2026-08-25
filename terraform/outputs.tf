output "vps_public_ip" {
  description = "Public IPv4 address of the provisioned SOC platform VPS"
  value       = try(contabo_instance.soc_platform.ip_config[0].v4[0].ip, null)
}

output "backend_url" {
  description = "Backend API base URL"
  value       = try("http://${contabo_instance.soc_platform.ip_config[0].v4[0].ip}:8000", null)
}

output "frontend_url" {
  description = "Frontend base URL"
  value       = try("http://${contabo_instance.soc_platform.ip_config[0].v4[0].ip}:3000", null)
}

output "n8n_url" {
  description = "n8n automation UI base URL"
  value       = try("http://${contabo_instance.soc_platform.ip_config[0].v4[0].ip}:5678", null)
}