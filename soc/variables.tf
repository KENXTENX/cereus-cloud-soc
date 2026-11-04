variable "subscription_id" {
  description = "Azure subscription ID (set via TF_VAR_subscription_id)"
  type        = string
}

variable "endpoint_vm_size" {
  description = "Endpoint VM size. Standard_B2s hit SkuNotAvailable (capacity) in eastus on 2026-11-03"
  type        = string
  default     = "Standard_B2als_v2"
}
