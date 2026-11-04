# Cloud SOC: Sentinel onboarding, detections, automation.
# Builds on the landing zone's workspace; state shares the Project 1 storage account.

terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.42"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # storage_account_name is passed at init time
  backend "azurerm" {
    resource_group_name = "rg-cereus-tfstate"
    container_name      = "tfstate"
    key                 = "cloud-soc.tfstate"
    use_azuread_auth    = true
  }
}

provider "azurerm" {
  features {}
  subscription_id     = var.subscription_id
  storage_use_azuread = true
}
