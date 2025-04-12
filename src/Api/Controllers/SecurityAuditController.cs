using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using SecurityAuditTool.Core.Interfaces;
using SecurityAuditTool.Core.Models;

namespace SecurityAuditTool.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SecurityAuditController : ControllerBase
    {
        private readonly IEnumerable<IVulnerabilityScanner> _scanners;
        private readonly IReportGenerator _reportGenerator;
        private readonly IRepository<ScanConfiguration> _configRepository;
        private readonly IRepository<ScanResult> _resultRepository;
        
        public SecurityAuditController(
            IEnumerable<IVulnerabilityScanner> scanners,
            IReportGenerator reportGenerator,
            IRepository<ScanConfiguration> configRepository,
            IRepository<ScanResult> resultRepository)
        {
            _scanners = scanners ?? throw new ArgumentNullException(nameof(scanners));
            _reportGenerator = reportGenerator ?? throw new ArgumentNullException(nameof(reportGenerator));
            _configRepository = configRepository ?? throw new ArgumentNullException(nameof(configRepository));
            _resultRepository = resultRepository ?? throw new ArgumentNullException(nameof(resultRepository));
        }
        
        [HttpGet("configurations")]
        public async Task<ActionResult<IEnumerable<ScanConfiguration>>> GetConfigurations()
        {
            var configurations = await _configRepository.GetAllAsync();
            return Ok(configurations);
        }
        
        [HttpGet("configurations/{id}")]
        public async Task<ActionResult<ScanConfiguration>> GetConfiguration(Guid id)
        {
            var configuration = await _configRepository.GetByIdAsync(id);
            
            if (configuration == null)
            {
                return NotFound();
            }
            
            return Ok(configuration);
        }
        
        [HttpPost("configurations")]
        public async Task<ActionResult<ScanConfiguration>> CreateConfiguration(ScanConfiguration configuration)
        {
            if (configuration == null)
            {
                return BadRequest();
            }
            
            configuration.Id = Guid.NewGuid();
            var result = await _configRepository.AddAsync(configuration);
            
            return CreatedAtAction(nameof(GetConfiguration), new { id = result.Id }, result);
        }
        
        [HttpPut("configurations/{id}")]
        public async Task<IActionResult> UpdateConfiguration(Guid id, ScanConfiguration configuration)
        {
            if (configuration == null || id != configuration.Id)
            {
                return BadRequest();
            }
            
            var existingConfig = await _configRepository.GetByIdAsync(id);
            
            if (existingConfig == null)
            {
                return NotFound();
            }
            
            await _configRepository.UpdateAsync(configuration);
            
            return NoContent();
        }
        
        [HttpDelete("configurations/{id}")]
        public async Task<IActionResult> DeleteConfiguration(Guid id)
        {
            var existingConfig = await _configRepository.GetByIdAsync(id);
            
            if (existingConfig == null)
            {
                return NotFound();
            }
            
            await _configRepository.DeleteAsync(id);
            
            return NoContent();
        }
        
        [HttpGet("results")]
        public async Task<ActionResult<IEnumerable<ScanResult>>> GetResults()
        {
            var results = await _resultRepository.GetAllAsync();
            return Ok(results);
        }
        
        [HttpGet("results/{id}")]
        public async Task<ActionResult<ScanResult>> GetResult(Guid id)
        {
            var result = await _resultRepository.GetByIdAsync(id);
            
            if (result == null)
            {
                return NotFound();
            }
            
            return Ok(result);
        }
        
        [HttpPost("scan")]
        public async Task<ActionResult<ScanResult>> StartScan(Guid configurationId)
        {
            var configuration = await _configRepository.GetByIdAsync(configurationId);
            
            if (configuration == null)
            {
                return NotFound($"Configuration with ID {configurationId} not found.");
            }
            
            var scanResults = new List<ScanResult>();
            
            // Run each scanner
            foreach (var scanner in _scanners)
            {
                var result = await scanner.ScanAsync(configuration);
                scanResults.Add(result);
                
                // Save each scan result
                await _resultRepository.AddAsync(result);
            }
            
            // Combine all results into a single result
            var combinedResult = CombineResults(scanResults);
            
            // Save the combined result
            await _resultRepository.AddAsync(combinedResult);
            
            return Ok(combinedResult);
        }
        
        [HttpGet("report/{id}")]
        public async Task<ActionResult> GenerateReport(Guid id, [FromQuery] ReportFormat format = ReportFormat.HTML)
        {
            var result = await _resultRepository.GetByIdAsync(id);
            
            if (result == null)
            {
                return NotFound($"Scan result with ID {id} not found.");
            }
            
            var reportPath = await _reportGenerator.GenerateReportAsync(result, format);
            
            // In a real implementation, you might return a file download or a URL to the report
            return Ok(new { ReportPath = reportPath });
        }
        
        [HttpGet("scanners")]
        public ActionResult<IEnumerable<object>> GetScanners()
        {
            var scannerInfoList = new List<object>();
            
            foreach (var scanner in _scanners)
            {
                scannerInfoList.Add(new
                {
                    Name = scanner.Name,
                    Description = scanner.Description,
                    VulnerabilityTypes = scanner.VulnerabilityTypes
                });
            }
            
            return Ok(scannerInfoList);
        }
        
        private ScanResult CombineResults(List<ScanResult> results)
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
            // This is a simplified example - in real-world, the compliance would be determined
            // by more complex rules, possibly checking against a compliance framework like PCI DSS, HIPAA, etc.
            combinedResult.Summary.ComplianceStatus = combinedResult.Summary.CriticalVulnerabilities == 0 && 
                                                  combinedResult.Summary.HighVulnerabilities <= 1;
            
            // Set risk score
            combinedResult.Summary.RiskScore = combinedResult.Summary.CalculateRiskScore();
            
            return combinedResult;
        }
    }
} 