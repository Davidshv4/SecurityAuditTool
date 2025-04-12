using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Xml.Linq;
using SecurityAuditTool.Core.Interfaces;
using SecurityAuditTool.Core.Models;

namespace SecurityAuditTool.Scanner
{
    /// <summary>
    /// Scanner that checks for outdated dependencies and security patches
    /// </summary>
    public class DependencyScanner : IVulnerabilityScanner
    {
        private readonly Dictionary<string, string> _latestPackageVersions = new Dictionary<string, string>
        {
            // This would normally be retrieved from a package repository API
            // These are just examples
            { "Newtonsoft.Json", "13.0.3" },
            { "Microsoft.AspNetCore.App", "7.0.11" },
            { "Microsoft.EntityFrameworkCore", "7.0.11" },
            { "Microsoft.Identity.Web", "2.13.3" },
            { "System.Data.SqlClient", "4.8.5" },
            { "log4net", "2.0.15" }
        };
        
        private readonly Dictionary<string, List<string>> _knownVulnerableVersions = new Dictionary<string, List<string>>
        {
            // This would normally be retrieved from a security database
            // These are just examples
            { "Newtonsoft.Json", new List<string> { "13.0.1", "12.0.3" } },
            { "Microsoft.AspNetCore.App", new List<string> { "6.0.0", "5.0.0" } },
            { "Microsoft.EntityFrameworkCore", new List<string> { "6.0.5", "5.0.10" } },
            { "log4net", new List<string> { "2.0.14", "2.0.13", "2.0.12" } }
        };
        
        public string Name => "Dependency Scanner";
        
        public string Description => "Scans for outdated dependencies and known vulnerable packages";
        
        public IEnumerable<string> VulnerabilityTypes => new List<string>
        {
            "Outdated Packages",
            "Known Vulnerable Dependencies",
            "Missing Security Patches"
        };
        
        public async Task<ScanResult> ScanAsync(ScanConfiguration configuration)
        {
            var result = new ScanResult
            {
                Id = Guid.NewGuid(),
                ScanConfigurationId = configuration.Id,
                StartTime = DateTime.UtcNow,
                Status = ScanStatus.InProgress
            };
            
            try
            {
                // Check if dependency scanning is enabled in the configuration
                if (!configuration.CheckDependencies)
                {
                    result.Status = ScanStatus.Completed;
                    result.EndTime = DateTime.UtcNow;
                    return result;
                }
                
                var vulnerabilities = new List<Vulnerability>();
                
                // For each target application, check its dependencies
                foreach (var app in configuration.TargetApplications)
                {
                    // Check .NET projects (csproj files)
                    var csprojFiles = Directory.GetFiles(app, "*.csproj", SearchOption.AllDirectories);
                    foreach (var csprojFile in csprojFiles)
                    {
                        var projectVulnerabilities = ScanDotNetProject(csprojFile);
                        vulnerabilities.AddRange(projectVulnerabilities);
                    }
                    
                    // Check package.json for Node.js projects
                    var packageJsonFiles = Directory.GetFiles(app, "package.json", SearchOption.AllDirectories);
                    foreach (var packageJsonFile in packageJsonFiles)
                    {
                        var nodeVulnerabilities = ScanNodeJsProject(packageJsonFile);
                        vulnerabilities.AddRange(nodeVulnerabilities);
                    }
                }
                
                // Update the result with the found vulnerabilities
                result.Vulnerabilities = vulnerabilities;
                
                // Update the summary with counts
                result.Summary.TotalVulnerabilities = vulnerabilities.Count;
                result.Summary.CriticalVulnerabilities = vulnerabilities.FindAll(v => v.Severity == VulnerabilitySeverity.Critical).Count;
                result.Summary.HighVulnerabilities = vulnerabilities.FindAll(v => v.Severity == VulnerabilitySeverity.High).Count;
                result.Summary.MediumVulnerabilities = vulnerabilities.FindAll(v => v.Severity == VulnerabilitySeverity.Medium).Count;
                result.Summary.LowVulnerabilities = vulnerabilities.FindAll(v => v.Severity == VulnerabilitySeverity.Low).Count;
                
                // Calculate risk score
                result.Summary.RiskScore = result.Summary.CalculateRiskScore();
                
                result.Status = ScanStatus.Completed;
            }
            catch (Exception ex)
            {
                result.Status = ScanStatus.Failed;
                result.ErrorMessage = ex.Message;
            }
            finally
            {
                result.EndTime = DateTime.UtcNow;
            }
            
            return result;
        }
        
        private List<Vulnerability> ScanDotNetProject(string csprojFile)
        {
            var vulnerabilities = new List<Vulnerability>();
            
            try
            {
                var document = XDocument.Load(csprojFile);
                var packageReferences = document.Descendants("PackageReference");
                
                foreach (var packageReference in packageReferences)
                {
                    var packageName = packageReference.Attribute("Include")?.Value;
                    var packageVersion = packageReference.Attribute("Version")?.Value;
                    
                    if (string.IsNullOrEmpty(packageName) || string.IsNullOrEmpty(packageVersion))
                    {
                        continue;
                    }
                    
                    // Check if the package has a known vulnerability
                    if (_knownVulnerableVersions.ContainsKey(packageName) && 
                        _knownVulnerableVersions[packageName].Contains(packageVersion))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Id = Guid.NewGuid(),
                            Name = $"Known Vulnerable Dependency: {packageName}",
                            Description = $"The package {packageName} version {packageVersion} has known security vulnerabilities.",
                            Severity = VulnerabilitySeverity.Critical,
                            Location = csprojFile,
                            AffectedComponent = packageName,
                            DetectedDate = DateTime.UtcNow,
                            RemedationSteps = $"Update {packageName} to the latest version.",
                            Status = VulnerabilityStatus.Open,
                            References = new List<string>
                            {
                                "https://nvd.nist.gov/vuln",
                                "https://github.com/advisories"
                            }
                        });
                    }
                    
                    // Check if the package is outdated
                    if (_latestPackageVersions.ContainsKey(packageName) && 
                        packageVersion != _latestPackageVersions[packageName])
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Id = Guid.NewGuid(),
                            Name = $"Outdated Dependency: {packageName}",
                            Description = $"The package {packageName} is using version {packageVersion}, but the latest version is {_latestPackageVersions[packageName]}.",
                            Severity = VulnerabilitySeverity.Medium,
                            Location = csprojFile,
                            AffectedComponent = packageName,
                            DetectedDate = DateTime.UtcNow,
                            RemedationSteps = $"Update {packageName} to version {_latestPackageVersions[packageName]}.",
                            Status = VulnerabilityStatus.Open
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Error scanning {csprojFile}: {ex.Message}");
            }
            
            return vulnerabilities;
        }
        
        private List<Vulnerability> ScanNodeJsProject(string packageJsonFile)
        {
            // This is a simplified implementation
            // In a real-world scenario, you would parse the package.json file and check dependencies
            return new List<Vulnerability>
            {
                new Vulnerability
                {
                    Id = Guid.NewGuid(),
                    Name = "Example Node.js Dependency Issue",
                    Description = "This is a placeholder for Node.js dependency scanning.",
                    Severity = VulnerabilitySeverity.Medium,
                    Location = packageJsonFile,
                    AffectedComponent = "Node.js Dependencies",
                    DetectedDate = DateTime.UtcNow,
                    RemedationSteps = "Update dependencies using npm audit fix.",
                    Status = VulnerabilityStatus.Open
                }
            };
        }
    }
} 