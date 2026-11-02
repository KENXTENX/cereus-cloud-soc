# Entra ID log streaming. Applied locally by a human with an Entra
# directory role; the CI identities deliberately do not have one.

terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.42"
    }
  }
  backend "azurerm" {
    resource_group_name = "rg-cereus-tfstate"
    container_name      = "tfstate"
    key                 = "entra.tfstate"
    use_azuread_auth    = true
  }
}

provider "azurerm" {
  features {}
  subscription_id     = var.subscription_id
  storage_use_azuread = true
}

variable "subscription_id" {
  type = string
}

data "azurerm_log_analytics_workspace" "core" {
  name                = "log-cereus-core"
  resource_group_name = "rg-cereus-core"
}

# Audit logs work on any license; the sign-in categories need Entra P1/P2
resource "azurerm_monitor_aad_diagnostic_setting" "entra" {
  name                       = "diag-entra-to-law"
  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.core.id

  enabled_log { category = "AuditLogs" }
  enabled_log { category = "SignInLogs" }
  enabled_log { category = "NonInteractiveUserSignInLogs" }
  enabled_log { category = "ServicePrincipalSignInLogs" }
  enabled_log { category = "ManagedIdentitySignInLogs" }
}
