# ---------------------------------------------------------------
# Phase 2: a small Windows endpoint in the landing zone's app
# subnet, so the SOC sees host telemetry (logons, process
# creation, account changes), not just control-plane logs.
# Access is Run Command only: no RDP, no one knows the password.
# ---------------------------------------------------------------
data "azurerm_subnet" "app" {
  name                 = "snet-app"
  virtual_network_name = "vnet-cereus-core"
  resource_group_name  = "rg-cereus-core"
}

locals {
  endpoint_tags = {
    project    = "cereus-cloud-soc"
    owner      = "kenny"
    managed_by = "terraform"
    env        = "lab"
    role       = "soc-endpoint"
  }
}

# The admin password is generated and lives only in encrypted,
# Entra-only Terraform state. Nobody signs in with it; the VM is
# driven through Run Command.
resource "random_password" "endpoint_admin" {
  length           = 32
  special          = true
  override_special = "!@#%^*-_=+"
}

# The app subnet has default outbound access disabled (Project 1),
# so the Azure Monitor Agent needs an explicit egress path.
# The subnet NSG denies all inbound from the internet, so this IP
# is used for egress only. Production path: Azure Monitor Private
# Link Scope and no public IP.
resource "azurerm_public_ip" "endpoint" {
  name                = "pip-soc-endpoint"
  resource_group_name = data.azurerm_log_analytics_workspace.core.resource_group_name
  location            = data.azurerm_log_analytics_workspace.core.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.endpoint_tags
}

resource "azurerm_network_interface" "endpoint" {
  #checkov:skip=CKV_AZURE_119:Egress for the monitoring agent in a private subnet; inbound from the internet is denied by the subnet NSG. Production path is Azure Monitor Private Link
  name                = "nic-soc-endpoint"
  resource_group_name = data.azurerm_log_analytics_workspace.core.resource_group_name
  location            = data.azurerm_log_analytics_workspace.core.location
  tags                = local.endpoint_tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = data.azurerm_subnet.app.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.endpoint.id
  }
}

resource "azurerm_windows_virtual_machine" "endpoint" {
  #checkov:skip=CKV_AZURE_50:The Azure Monitor Agent extension is the purpose of this VM
  name                       = "vm-soc-endpoint"
  computer_name              = "soc-endpoint"
  resource_group_name        = data.azurerm_log_analytics_workspace.core.resource_group_name
  location                   = data.azurerm_log_analytics_workspace.core.location
  size                       = var.endpoint_vm_size
  admin_username             = "socadmin"
  admin_password             = random_password.endpoint_admin.result
  network_interface_ids      = [azurerm_network_interface.endpoint.id]
  encryption_at_host_enabled = true
  automatic_updates_enabled  = true
  provision_vm_agent         = true
  tags                       = local.endpoint_tags

  # The monitoring agent authenticates with this identity
  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-smalldisk-g2"
    version   = "latest"
  }
}

# Cost guardrail: the VM deallocates every evening even if I forget
resource "azurerm_dev_test_global_vm_shutdown_schedule" "endpoint" {
  virtual_machine_id    = azurerm_windows_virtual_machine.endpoint.id
  location              = azurerm_windows_virtual_machine.endpoint.location
  enabled               = true
  daily_recurrence_time = "1900"
  timezone              = "Eastern Standard Time"
  tags                  = local.endpoint_tags

  notification_settings {
    enabled = false
  }
}
