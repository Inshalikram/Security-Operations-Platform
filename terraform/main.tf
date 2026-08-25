terraform {
  required_version = ">= 1.5.0"

  required_providers {
    contabo = {
      source  = "contabo/contabo"
      version = ">= 0.1.44"
    }
  }
}

# Contabo API credentials are read from environment variables so they are
# never hardcoded in this file or committed to version control:
#   TF_VAR_contabo_client_id
#   TF_VAR_contabo_client_secret
#   TF_VAR_contabo_user
#   TF_VAR_contabo_password
provider "contabo" {
  oauth2_client_id     = var.contabo_client_id
  oauth2_client_secret = var.contabo_client_secret
  oauth2_user           = var.contabo_user
  oauth2_pass            = var.contabo_password
}

# ---------------------------------------------------------------------------
# SOC Platform VPS instance
#
# This mirrors the VPS that was actually provisioned manually through the
# Contabo control panel for the live deployment. This configuration lets the
# same instance profile be re-provisioned in a repeatable, reviewable way,
# without needing to click through the web UI again.
# ---------------------------------------------------------------------------
resource "contabo_instance" "soc_platform" {
  display_name = var.instance_display_name
  product_id    = var.instance_product_id # VPS size/plan, e.g. "V45" (~8GB RAM tier)
  region        = var.contabo_region

  image_id = var.instance_image_id # Ubuntu 22.04 LTS

  ssh_keys = var.ssh_key_ids

  # Bootstraps Docker, clones the repo, and brings the whole stack up on
  # first boot — same steps that were run manually during the actual
  # deployment (see docs/06-deployment-guide.md).
  user_data = file("${path.module}/cloud-init.yml")

  period = 1 # billed monthly
}

output "instance_summary" {
  description = "Key details of the provisioned SOC platform instance"
  value = {
    id          = contabo_instance.soc_platform.id
    display_name = contabo_instance.soc_platform.display_name
    ip_config    = contabo_instance.soc_platform.ip_config
  }
}