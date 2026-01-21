# Exivity MCP Server

An MCP (Model Context Protocol) server for interacting with the **Exivity** API, with built-in support for the **FinOps FOCUS (FinOps Open Cost and Usage Specification)** documentation standard.

## 🚀 Purpose

The Exivity MCP Server bridges the gap between your Exivity billing data and AI assistants (like Claude). It enables autonomous retrieval of billing reports, data normalization, and seamless transformation into the **FOCUS 1.0** standard, allowing for standardized cost analysis across multiple cloud providers and on-premise infrastructure managed by Exivity.

## 💡 Why FOCUS?

In the evolving field of Cloud Financial Management, the **FinOps FOCUS** standard is crucial. It provides:

- **Interoperability**: A common schema for billing data regardless of the provider (AWS, Azure, GCP, or custom Exivity sources).
- **Consistency**: Standardized column names and values (e.g., `BilledCost`, `BillingAccountId`) that remove ambiguity from cost reporting.
- **AI-Readiness**: Standardized schemas make it significantly easier for AI models to perform accurate, cross-platform cost optimizations and trend analysis.

This server automates the heavy lifting of mapping proprietary Exivity fields to the FOCUS standard, enabling immediate, standard-compliant reporting.

## ✨ Features

- **Standard Reporting**: Run any Exivity report by ID with flexible parameters (start/end dates, dimensions, filters).
- **FOCUS Transformation**: Automatically transform Exivity output into FOCUS 1.0 JSON format.
- **Rich Metadata**: Automatically includes dimensions like `accounts`, `services`, and `instances` to ensure high granularity.
- **Smart Mapping**: Intelligent field mapping (e.g., `total_charge` -> `BilledCost`) based on Exivity's native structure.
- **Secure Authentication**: Supports Bearer token and Basic auth.
- **Streamable**: Built with `FastMCP` for efficient, streamable tool execution.

## 🛠 Installation

Add the following to your MCP configuration file (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "exivity": {
      "command": "python3",
      "args": ["/path/to/Exivity_mcp/exivity_mcp_server.py"],
      "env": {
        "EXIVITY_BASE_URL": "https://your-exivity-instance.com",
        "EXIVITY_USERNAME": "your-username",
        "EXIVITY_PASSWORD": "your-password",
        "EXIVITY_SSL_VERIFY": "true"
      }
    }
  }
}
```

## 🧰 Tools

### `run_report`
Runs a raw Exivity report and returns the data as-is.
- **Parameters**: `report_id`, `start`, `end`, `dimension`, `include`, etc.

### `run_focus_report`
Runs an Exivity report and transforms the result into the **FinOps FOCUS 1.0** schema.
- **Parameters**: `report_id`, `start`, `end`, and optional `custom_mapping`.
- **Note**: Defaults to requesting `accounts,services,instances` dimensions for maximum detail.

## 📊 Examples

### Running a FOCUS-compliant report
**Query**: *"Run Exivity report 5 for last month and show it in FOCUS format"*

**Example Output**:
```json
{
  "focus_version": "1.0",
  "record_count": 1,
  "data": [
    {
      "BillingAccountId": "123456789",
      "BillingAccountName": "Engineering-Prod",
      "BilledCost": 1250.75,
      "ServiceName": "Virtual Machines",
      "UsageQuantity": 720,
      "UsageUnit": "Hrs",
      "BillingPeriodStart": "2025-12-01",
      "BillingPeriodEnd": "2025-12-31"
    }
  ]
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit Pull Requests or open issues for new field mappings or feature requests.

---
*Created by the Exivity FinOps Team*
