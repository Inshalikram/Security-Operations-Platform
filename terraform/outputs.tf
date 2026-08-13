output "vps_public_ip" {
  value = openstack_networking_floatingip_v2.sop_fip.address
}

output "backend_url" {
  value = "http://${openstack_networking_floatingip_v2.sop_fip.address}:8000"
}

output "n8n_url" {
  value = "http://${openstack_networking_floatingip_v2.sop_fip.address}:5678"
}