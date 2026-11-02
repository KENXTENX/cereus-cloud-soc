# ---------------------------------------------------------------
# Turn the landing zone's workspace into a SIEM
# ---------------------------------------------------------------
resource "azurerm_sentinel_log_analytics_workspace_onboarding" "core" {
  workspace_id = data.azurerm_log_analytics_workspace.core.id
}
