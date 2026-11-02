# Consume the landing zone's workspace; never recreate it here
data "azurerm_log_analytics_workspace" "core" {
  name                = "log-cereus-core"
  resource_group_name = "rg-cereus-core"
}
