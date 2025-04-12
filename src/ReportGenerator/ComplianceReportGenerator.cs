using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityAuditTool.Core.Interfaces;
using SecurityAuditTool.Core.Models;

namespace SecurityAuditTool.ReportGenerator
{
    /// <summary>
    /// Generates compliance reports based on scan results
    /// </summary>
    public class ComplianceReportGenerator : IReportGenerator
    {
        private readonly string _reportOutputPath;
        
        public ComplianceReportGenerator(string reportOutputPath)
        {
            _reportOutputPath = reportOutputPath ?? Path.Combine(Environment.CurrentDirectory, "Reports");
            
            // Ensure the output directory exists
            if (!Directory.Exists(_reportOutputPath))
            {
                Directory.CreateDirectory(_reportOutputPath);
            }
        }
        
        public async Task<string> GenerateReportAsync(ScanResult scanResult, ReportFormat format)
        {
            if (scanResult == null)
            {
                throw new ArgumentNullException(nameof(scanResult));
            }
            
            string reportPath;
            
            switch (format)
            {
                case ReportFormat.HTML:
                    reportPath = await GenerateHtmlReportAsync(scanResult);
                    break;
                case ReportFormat.PDF:
                    reportPath = await GeneratePdfReportAsync(scanResult);
                    break;
                case ReportFormat.JSON:
                    reportPath = await GenerateJsonReportAsync(scanResult);
                    break;
                case ReportFormat.XML:
                    reportPath = await GenerateXmlReportAsync(scanResult);
                    break;
                case ReportFormat.CSV:
                    reportPath = await GenerateCsvReportAsync(scanResult);
                    break;
                default:
                    throw new ArgumentException($"Unsupported report format: {format}");
            }
            
            return reportPath;
        }
        
        private async Task<string> GenerateHtmlReportAsync(ScanResult scanResult)
        {
            // In a real implementation, you would use a template engine like Razor
            // This is a simplified example
            
            var fileName = $"SecurityReport_{scanResult.Id}_{DateTime.UtcNow:yyyyMMddHHmmss}.html";
            var filePath = Path.Combine(_reportOutputPath, fileName);
            
            var builder = new StringBuilder();
            builder.AppendLine("<!DOCTYPE html>");
            builder.AppendLine("<html>");
            builder.AppendLine("<head>");
            builder.AppendLine("    <title>Security Compliance Report</title>");
            builder.AppendLine("    <style>");
            builder.AppendLine("        body { font-family: Arial, sans-serif; margin: 20px; }");
            builder.AppendLine("        h1 { color: #2c3e50; }");
            builder.AppendLine("        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }");
            builder.AppendLine("        .vulnerability { background-color: #ffffff; padding: 15px; border: 1px solid #dee2e6; border-radius: 5px; margin-bottom: 10px; }");
            builder.AppendLine("        .critical { border-left: 5px solid #dc3545; }");
            builder.AppendLine("        .high { border-left: 5px solid #fd7e14; }");
            builder.AppendLine("        .medium { border-left: 5px solid #ffc107; }");
            builder.AppendLine("        .low { border-left: 5px solid #20c997; }");
            builder.AppendLine("        table { width: 100%; border-collapse: collapse; }");
            builder.AppendLine("        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #dee2e6; }");
            builder.AppendLine("    </style>");
            builder.AppendLine("</head>");
            builder.AppendLine("<body>");
            
            // Header
            builder.AppendLine("    <h1>Security Compliance Report</h1>");
            builder.AppendLine("    <p>Generated on: " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC</p>");
            
            // Summary
            builder.AppendLine("    <div class=\"summary\">");
            builder.AppendLine("        <h2>Scan Summary</h2>");
            builder.AppendLine("        <table>");
            builder.AppendLine("            <tr><th>Start Time:</th><td>" + scanResult.StartTime.ToString("yyyy-MM-dd HH:mm:ss") + " UTC</td></tr>");
            builder.AppendLine("            <tr><th>End Time:</th><td>" + scanResult.EndTime.ToString("yyyy-MM-dd HH:mm:ss") + " UTC</td></tr>");
            builder.AppendLine("            <tr><th>Status:</th><td>" + scanResult.Status + "</td></tr>");
            builder.AppendLine("            <tr><th>Total Vulnerabilities:</th><td>" + scanResult.Summary.TotalVulnerabilities + "</td></tr>");
            builder.AppendLine("            <tr><th>Critical Vulnerabilities:</th><td>" + scanResult.Summary.CriticalVulnerabilities + "</td></tr>");
            builder.AppendLine("            <tr><th>High Vulnerabilities:</th><td>" + scanResult.Summary.HighVulnerabilities + "</td></tr>");
            builder.AppendLine("            <tr><th>Medium Vulnerabilities:</th><td>" + scanResult.Summary.MediumVulnerabilities + "</td></tr>");
            builder.AppendLine("            <tr><th>Low Vulnerabilities:</th><td>" + scanResult.Summary.LowVulnerabilities + "</td></tr>");
            builder.AppendLine("            <tr><th>Risk Score:</th><td>" + scanResult.Summary.RiskScore + "</td></tr>");
            builder.AppendLine("            <tr><th>Compliance Status:</th><td>" + (scanResult.Summary.ComplianceStatus ? "Compliant" : "Non-Compliant") + "</td></tr>");
            builder.AppendLine("        </table>");
            builder.AppendLine("    </div>");
            
            // Vulnerabilities
            builder.AppendLine("    <h2>Vulnerabilities</h2>");
            
            foreach (var vuln in scanResult.Vulnerabilities.OrderByDescending(v => v.Severity))
            {
                string severityClass = "";
                switch (vuln.Severity)
                {
                    case VulnerabilitySeverity.Critical:
                        severityClass = "critical";
                        break;
                    case VulnerabilitySeverity.High:
                        severityClass = "high";
                        break;
                    case VulnerabilitySeverity.Medium:
                        severityClass = "medium";
                        break;
                    case VulnerabilitySeverity.Low:
                        severityClass = "low";
                        break;
                }
                
                builder.AppendLine($"    <div class=\"vulnerability {severityClass}\">");
                builder.AppendLine($"        <h3>{vuln.Name}</h3>");
                builder.AppendLine($"        <p><strong>Severity:</strong> {vuln.Severity}</p>");
                builder.AppendLine($"        <p><strong>Description:</strong> {vuln.Description}</p>");
                builder.AppendLine($"        <p><strong>Location:</strong> {vuln.Location}</p>");
                builder.AppendLine($"        <p><strong>Affected Component:</strong> {vuln.AffectedComponent}</p>");
                builder.AppendLine($"        <p><strong>Remediation Steps:</strong> {vuln.RemedationSteps}</p>");
                builder.AppendLine($"        <p><strong>Status:</strong> {vuln.Status}</p>");
                
                if (vuln.References.Any())
                {
                    builder.AppendLine($"        <p><strong>References:</strong></p>");
                    builder.AppendLine($"        <ul>");
                    
                    foreach (var reference in vuln.References)
                    {
                        builder.AppendLine($"            <li><a href=\"{reference}\" target=\"_blank\">{reference}</a></li>");
                    }
                    
                    builder.AppendLine($"        </ul>");
                }
                
                builder.AppendLine("    </div>");
            }
            
            // Compliance checks
            builder.AppendLine("    <h2>Compliance Checks</h2>");
            
            // Passed checks
            builder.AppendLine("    <h3>Passed Checks</h3>");
            
            if (scanResult.Summary.PassedComplianceChecks.Any())
            {
                builder.AppendLine("    <ul>");
                
                foreach (var check in scanResult.Summary.PassedComplianceChecks)
                {
                    builder.AppendLine($"        <li>{check}</li>");
                }
                
                builder.AppendLine("    </ul>");
            }
            else
            {
                builder.AppendLine("    <p>No passed compliance checks.</p>");
            }
            
            // Failed checks
            builder.AppendLine("    <h3>Failed Checks</h3>");
            
            if (scanResult.Summary.FailedComplianceChecks.Any())
            {
                builder.AppendLine("    <ul>");
                
                foreach (var check in scanResult.Summary.FailedComplianceChecks)
                {
                    builder.AppendLine($"        <li>{check}</li>");
                }
                
                builder.AppendLine("    </ul>");
            }
            else
            {
                builder.AppendLine("    <p>No failed compliance checks.</p>");
            }
            
            builder.AppendLine("</body>");
            builder.AppendLine("</html>");
            
            await File.WriteAllTextAsync(filePath, builder.ToString());
            
            return filePath;
        }
        
        private async Task<string> GeneratePdfReportAsync(ScanResult scanResult)
        {
            // In a real implementation, you would use a PDF library like iTextSharp or PdfSharp
            // This is a simplified example that just creates a text file
            
            var fileName = $"SecurityReport_{scanResult.Id}_{DateTime.UtcNow:yyyyMMddHHmmss}.txt";
            var filePath = Path.Combine(_reportOutputPath, fileName);
            
            var builder = new StringBuilder();
            builder.AppendLine("SECURITY COMPLIANCE REPORT");
            builder.AppendLine($"Generated on: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            builder.AppendLine();
            
            // Summary
            builder.AppendLine("SCAN SUMMARY");
            builder.AppendLine($"Start Time: {scanResult.StartTime:yyyy-MM-dd HH:mm:ss} UTC");
            builder.AppendLine($"End Time: {scanResult.EndTime:yyyy-MM-dd HH:mm:ss} UTC");
            builder.AppendLine($"Status: {scanResult.Status}");
            builder.AppendLine($"Total Vulnerabilities: {scanResult.Summary.TotalVulnerabilities}");
            builder.AppendLine($"Critical Vulnerabilities: {scanResult.Summary.CriticalVulnerabilities}");
            builder.AppendLine($"High Vulnerabilities: {scanResult.Summary.HighVulnerabilities}");
            builder.AppendLine($"Medium Vulnerabilities: {scanResult.Summary.MediumVulnerabilities}");
            builder.AppendLine($"Low Vulnerabilities: {scanResult.Summary.LowVulnerabilities}");
            builder.AppendLine($"Risk Score: {scanResult.Summary.RiskScore}");
            builder.AppendLine($"Compliance Status: {(scanResult.Summary.ComplianceStatus ? "Compliant" : "Non-Compliant")}");
            builder.AppendLine();
            
            // Vulnerabilities
            builder.AppendLine("VULNERABILITIES");
            builder.AppendLine();
            
            foreach (var vuln in scanResult.Vulnerabilities.OrderByDescending(v => v.Severity))
            {
                builder.AppendLine($"Name: {vuln.Name}");
                builder.AppendLine($"Severity: {vuln.Severity}");
                builder.AppendLine($"Description: {vuln.Description}");
                builder.AppendLine($"Location: {vuln.Location}");
                builder.AppendLine($"Affected Component: {vuln.AffectedComponent}");
                builder.AppendLine($"Remediation Steps: {vuln.RemedationSteps}");
                builder.AppendLine($"Status: {vuln.Status}");
                
                if (vuln.References.Any())
                {
                    builder.AppendLine("References:");
                    
                    foreach (var reference in vuln.References)
                    {
                        builder.AppendLine($"- {reference}");
                    }
                }
                
                builder.AppendLine();
            }
            
            // Compliance checks
            builder.AppendLine("COMPLIANCE CHECKS");
            builder.AppendLine();
            
            // Passed checks
            builder.AppendLine("Passed Checks:");
            
            if (scanResult.Summary.PassedComplianceChecks.Any())
            {
                foreach (var check in scanResult.Summary.PassedComplianceChecks)
                {
                    builder.AppendLine($"- {check}");
                }
            }
            else
            {
                builder.AppendLine("No passed compliance checks.");
            }
            
            builder.AppendLine();
            
            // Failed checks
            builder.AppendLine("Failed Checks:");
            
            if (scanResult.Summary.FailedComplianceChecks.Any())
            {
                foreach (var check in scanResult.Summary.FailedComplianceChecks)
                {
                    builder.AppendLine($"- {check}");
                }
            }
            else
            {
                builder.AppendLine("No failed compliance checks.");
            }
            
            await File.WriteAllTextAsync(filePath, builder.ToString());
            
            return filePath;
        }
        
        private async Task<string> GenerateJsonReportAsync(ScanResult scanResult)
        {
            // In a real implementation, you would use a JSON library like Newtonsoft.Json
            // This is a simplified placeholder
            
            var fileName = $"SecurityReport_{scanResult.Id}_{DateTime.UtcNow:yyyyMMddHHmmss}.json";
            var filePath = Path.Combine(_reportOutputPath, fileName);
            
            // Placeholder for actual JSON serialization
            await File.WriteAllTextAsync(filePath, "JSON report would be generated here");
            
            return filePath;
        }
        
        private async Task<string> GenerateXmlReportAsync(ScanResult scanResult)
        {
            // In a real implementation, you would use XML serialization
            // This is a simplified placeholder
            
            var fileName = $"SecurityReport_{scanResult.Id}_{DateTime.UtcNow:yyyyMMddHHmmss}.xml";
            var filePath = Path.Combine(_reportOutputPath, fileName);
            
            // Placeholder for actual XML serialization
            await File.WriteAllTextAsync(filePath, "XML report would be generated here");
            
            return filePath;
        }
        
        private async Task<string> GenerateCsvReportAsync(ScanResult scanResult)
        {
            var fileName = $"SecurityReport_{scanResult.Id}_{DateTime.UtcNow:yyyyMMddHHmmss}.csv";
            var filePath = Path.Combine(_reportOutputPath, fileName);
            
            var builder = new StringBuilder();
            
            // Header
            builder.AppendLine("Id,Name,Severity,Description,Location,AffectedComponent,DetectedDate,Status,RemediationSteps");
            
            // Vulnerabilities
            foreach (var vuln in scanResult.Vulnerabilities)
            {
                builder.AppendLine($"{vuln.Id},{EscapeCsvField(vuln.Name)},{vuln.Severity},{EscapeCsvField(vuln.Description)},{EscapeCsvField(vuln.Location)},{EscapeCsvField(vuln.AffectedComponent)},{vuln.DetectedDate:yyyy-MM-dd HH:mm:ss},{vuln.Status},{EscapeCsvField(vuln.RemedationSteps)}");
            }
            
            await File.WriteAllTextAsync(filePath, builder.ToString());
            
            return filePath;
        }
        
        private string EscapeCsvField(string field)
        {
            if (string.IsNullOrEmpty(field))
            {
                return string.Empty;
            }
            
            return $"\"{field.Replace("\"", "\"\"").Replace("\r", "").Replace("\n", "")}\"";
        }
    }
} 