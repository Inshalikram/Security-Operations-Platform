terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.53"
    }
  }
}

provider "openstack" {
  auth_url    = var.ovh_auth_url
  domain_name = "default"
  tenant_id   = var.ovh_project_id
  user_name   = var.ovh_username
  password    = var.ovh_password
  region      = var.ovh_region
}

# ── Network ──
resource "openstack_networking_network_v2" "sop_network" {
  name           = "sop-network"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "sop_subnet" {
  name       = "sop-subnet"
  network_id = openstack_networking_network_v2.sop_network.id
  cidr       = "192.168.100.0/24"
  ip_version = 4
}

# ── Security Group (firewall rules) ──
resource "openstack_networking_secgroup_v2" "sop_secgroup" {
  name        = "sop-secgroup"
  description = "SOC Platform allowed ports"
}

resource "openstack_networking_secgroup_rule_v2" "ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sop_secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "http" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sop_secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "https" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sop_secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "backend_api" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8000
  port_range_max    = 8000
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.sop_secgroup.id
}

# ── VPS Instance ──
resource "openstack_compute_instance_v2" "sop_vps" {
  name            = "sop-production"
  image_name      = "Ubuntu 22.04"
  flavor_name     = var.instance_flavor
  key_pair        = var.ssh_keypair_name
  security_groups = [openstack_networking_secgroup_v2.sop_secgroup.name]

  network {
    name = openstack_networking_network_v2.sop_network.name
  }

  user_data = file("${path.module}/cloud-init.yml")
}

# ── Floating (public) IP ──
resource "openstack_networking_floatingip_v2" "sop_fip" {
  pool = var.external_network_name
}

resource "openstack_compute_floatingip_associate_v2" "sop_fip_assoc" {
  floating_ip = openstack_networking_floatingip_v2.sop_fip.address
  instance_id = openstack_compute_instance_v2.sop_vps.id
}