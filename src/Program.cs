using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecurityAuditTool.Api.Controllers;
using SecurityAuditTool.Core.Interfaces;
using SecurityAuditTool.Core.Models;
using SecurityAuditTool.Database;
using SecurityAuditTool.ReportGenerator;
using SecurityAuditTool.Scanner;

namespace SecurityAuditTool
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // Setup dependency injection
            var serviceProvider = ConfigureServices();
            
            Console.WriteLine("Enterprise Security Audit Tool");
            Console.WriteLine("==============================");
            Console.WriteLine();
            
            // Create a sample scan configuration
            var config = CreateSampleScanConfiguration();
            
            // Display available scanners
            var scanners = serviceProvider.GetServices<IVulnerabilityScanner>();
            Console.WriteLine("Available Scanners:");
            foreach (var scanner in scanners)
            {
                Console.WriteLine($"- {scanner.Name}");
                Console.WriteLine($"  {scanner.Description}");
                Console.WriteLine();
            }
            
            // Run the scanners
            Console.WriteLine("Running security scan...");
            Console.WriteLine();
            
            var scanResults = new List<ScanResult>();
            foreach (var scanner in scanners)
            {
                Console.WriteLine($"Running {scanner.Name}...");
                var result = await scanner.ScanAsync(config);
                scanResults.Add(result);
                
                Console.WriteLine($"Found {result.Vulnerabilities.Count} vulnerabilities.");
                Console.WriteLine();
            }
            
            // Combine the results
            var combinedResult = CombineResults(scanResults);
            
            // Display summary
            Console.WriteLine("Scan Summary:");
            Console.WriteLine($"Total Vulnerabilities: {combinedResult.Summary.TotalVulnerabilities}");
            Console.WriteLine($"Critical Vulnerabilities: {combinedResult.Summary.CriticalVulnerabilities}");
            Console.WriteLine($"High Vulnerabilities: {combinedResult.Summary.HighVulnerabilities}");
            Console.WriteLine($"Medium Vulnerabilities: {combinedResult.Summary.MediumVulnerabilities}");
            Console.WriteLine($"Low Vulnerabilities: {combinedResult.Summary.LowVulnerabilities}");
            Console.WriteLine($"Risk Score: {combinedResult.Summary.RiskScore}");
            Console.WriteLine($"Compliance Status: {(combinedResult.Summary.ComplianceStatus ? "Compliant" : "Non-Compliant")}");
            Console.WriteLine();
            
            // Generate reports
            var reportGenerator = serviceProvider.GetRequiredService<IReportGenerator>();
            
            Console.WriteLine("Generating reports...");
            
            string htmlReport = await reportGenerator.GenerateReportAsync(combinedResult, ReportFormat.HTML);
            Console.WriteLine($"HTML Report: {htmlReport}");
            
            string pdfReport = await reportGenerator.GenerateReportAsync(combinedResult, ReportFormat.PDF);
            Console.WriteLine($"PDF Report: {pdfReport}");
            
            string csvReport = await reportGenerator.GenerateReportAsync(combinedResult, ReportFormat.CSV);
            Console.WriteLine($"CSV Report: {csvReport}");
            
            Console.WriteLine();
            Console.WriteLine("Security scan completed. Press any key to exit.");
            Console.ReadKey();
        }
        
        private static ServiceProvider ConfigureServices()
        {
            // Create configuration
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true)
                .Build();
            
            // Setup DI
            var services = new ServiceCollection();
            
            // Add scanners
            services.AddSingleton<IVulnerabilityScanner, AuthenticationScanner>();
            services.AddSingleton<IVulnerabilityScanner, DependencyScanner>();
            
            // Add report generator
            services.AddSingleton<IReportGenerator>(provider => 
                new ComplianceReportGenerator(Path.Combine(Directory.GetCurrentDirectory(), "Reports")));
            
            // Add configuration
            services.AddSingleton<IConfiguration>(configuration);
            
            // Add repositories
            services.AddSingleton<IRepository<ScanConfiguration>>(provider => 
                new SqlRepository<ScanConfiguration>(configuration, "ScanConfigurations"));
            services.AddSingleton<IRepository<ScanResult>>(provider => 
                new SqlRepository<ScanResult>(configuration, "ScanResults"));
            
            return services.BuildServiceProvider();
        }
        
        private static ScanConfiguration CreateSampleScanConfiguration()
        {
            return new ScanConfiguration
            {
                Id = Guid.NewGuid(),
                Name = "Sample Scan",
                Description = "A sample security scan configuration",
                TargetUrls = new List<string>
                {
                    "https://example.com/app1",
                    "https://example.com/app2"
                },
                TargetApplications = new List<string>
                {
                    @"C:\SampleApps\App1",
                    @"C:\SampleApps\App2"
                },
                CheckAuthentication = true,
                CheckAuthorization = true,
                CheckDependencies = true,
                CheckCommonVulnerabilities = true,
                GenerateComplianceReport = true,
                AuthenticationSettings = new AuthenticationSettings
                {
                    Username = "test-user",
                    Password = "password",
                    AuthType = AuthenticationType.Basic,
                    LoginUrl = "https://example.com/login"
                },
                Schedule = new ScanSchedule
                {
                    IsRecurring = true,
                    RecurrenceType = RecurrenceType.Weekly,
                    StartDate = DateTime.Now,
                    StartTime = new TimeSpan(9, 0, 0) // 9:00 AM
                }
            };
        }
        
        private static ScanResult CombineResults(List<ScanResult> results)
        {
            if (results == null || results.Count == 0)
            {
                throw new ArgumentException("Cannot combine empty results list");
            }
            
            // Create a new combined result
            var combinedResult = new ScanResult
            {
                Id = Guid.NewGuid(),
                ScanConfigurationId = results[0].ScanConfigurationId,
                StartTime = results.MinBy(r => r.StartTime).StartTime,
                EndTime = results.MaxBy(r => r.EndTime).EndTime,
                Status = results.Any(r => r.Status == ScanStatus.Failed) ? ScanStatus.Failed : ScanStatus.Completed,
                Vulnerabilities = new List<Vulnerability>(),
                Summary = new ScanSummary()
            };
            
            // Combine all vulnerabilities
            foreach (var result in results)
            {
                combinedResult.Vulnerabilities.AddRange(result.Vulnerabilities);
                
                if (result.Status == ScanStatus.Failed)
                {
                    combinedResult.ErrorMessage += $"{result.ErrorMessage}; ";
                }
            }
            
            // Update summary
            combinedResult.Summary.TotalVulnerabilities = combinedResult.Vulnerabilities.Count;
            combinedResult.Summary.CriticalVulnerabilities = combinedResult.Vulnerabilities.FindAll(v => v.Severity == VulnerabilitySeverity.Critical).Count;
            combinedResult.Summary.HighVulnerabilities = combinedResult.Vulnerabilities.FindAll(v => v.Severity == VulnerabilitySeverity.High).Count;
            combinedResult.Summary.MediumVulnerabilities = combinedResult.Vulnerabilities.FindAll(v => v.Severity == VulnerabilitySeverity.Medium).Count;
            combinedResult.Summary.LowVulnerabilities = combinedResult.Vulnerabilities.FindAll(v => v.Severity == VulnerabilitySeverity.Low).Count;
            
            // Calculate compliance status
            combinedResult.Summary.ComplianceStatus = combinedResult.Summary.CriticalVulnerabilities == 0 && 
                                                  combinedResult.Summary.HighVulnerabilities <= 1;
            
            // Add some sample compliance checks
            if (combinedResult.Summary.ComplianceStatus)
            {
                combinedResult.Summary.PassedComplianceChecks.Add("Authentication mechanisms are sufficiently secure");
                combinedResult.Summary.PassedComplianceChecks.Add("All dependencies are up-to-date");
                combinedResult.Summary.PassedComplianceChecks.Add("No critical vulnerabilities detected");
            }
            else
            {
                if (combinedResult.Summary.CriticalVulnerabilities > 0)
                {
                    combinedResult.Summary.FailedComplianceChecks.Add("Critical vulnerabilities must be fixed");
                }
                
                if (combinedResult.Summary.HighVulnerabilities > 1)
                {
                    combinedResult.Summary.FailedComplianceChecks.Add("Too many high severity vulnerabilities");
                }
            }
            
            // Set risk score
            combinedResult.Summary.RiskScore = combinedResult.Summary.CalculateRiskScore();
            
            return combinedResult;
        }
    }
} 