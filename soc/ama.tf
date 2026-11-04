# ---------------------------------------------------------------
# Host telemetry into the SOC: Azure Monitor Agent on the endpoint,
# plus a data collection rule for the Security events the Phase 3
# detections and Phase 4 triggers need.
#   4624 logon success      4625 logon failure
#   4688 process creation   4720 user account created
#   4732 member added to a local security group
# ---------------------------------------------------------------
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.endpoint.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = local.endpoint_tags
}

resource "azurerm_monitor_data_collection_rule" "security_events" {
  name                = "dcr-soc-security-events"
  resource_group_name = data.azurerm_log_analytics_workspace.core.resource_group_name
  location            = data.azurerm_log_analytics_workspace.core.location
  kind                = "Windows"
  tags                = local.endpoint_tags

  destinations {
    log_analytics {
      name                  = "law-core"
      workspace_resource_id = data.azurerm_log_analytics_workspace.core.id
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["law-core"]
  }

  data_sources {
    windows_event_log {
      name    = "security-events"
      streams = ["Microsoft-SecurityEvent"]
      x_path_queries = [
        "Security!*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4732)]]"
      ]
    }
  }
}

resource "azurerm_monitor_data_collection_rule_association" "endpoint" {
  name                    = "dcra-soc-endpoint"
  target_resource_id      = azurerm_windows_virtual_machine.endpoint.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.security_events.id
}
