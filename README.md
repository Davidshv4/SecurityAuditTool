# Enterprise Security Audit Tool

An automated security audit tool for scanning enterprise applications for security vulnerabilities and generating compliance reports.

## Features

- **Authentication & Authorization Checks**: Analyzes applications for proper authentication mechanisms and authorization controls
- **Dependency Scanning**: Scans for outdated dependencies and security patches
- **Compliance Reporting**: Generates detailed reports for IT teams

## Tech Stack

- C# / .NET 6.0
- SQL Server
- REST APIs

## Project Structure

- **Core**: Core models, interfaces, and shared components
- **Scanner**: Security vulnerability scanning engines
  - Authentication Scanner: Checks for authentication and authorization vulnerabilities
  - Dependency Scanner: Identifies outdated dependencies and known vulnerabilities
- **Api**: REST API controllers for interacting with the tool
- **Database**: Data access layer and repositories
- **ReportGenerator**: Generates compliance reports in multiple formats (HTML, PDF, CSV)

## Getting Started

### Prerequisites

- .NET 6.0 SDK or later
- SQL Server (for storing scan configurations and results)

### Installation

1. Clone the repository
   ```
   git clone https://github.com/david-gromoff/SecurityAuditTool.git
   ```

2. Navigate to the project directory
   ```
   cd SecurityAuditTool
   ```

3. Build the project
   ```
   dotnet build
   ```

4. Configure the database connection in `appsettings.json`

5. Run the application
   ```
   dotnet run
   ```

## Usage

The application provides both a command-line interface and a REST API for integration with other systems:

### Command Line

```
dotnet run -- --target https://example.com/app1 --scan-type full
```

### API

```
POST /api/securityaudit/scan
{
  "targetUrls": ["https://example.com/app1"],
  "scanType": "full",
  "generateReport": true
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 