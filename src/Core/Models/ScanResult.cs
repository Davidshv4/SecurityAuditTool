using System;
using System.Collections.Generic;

namespace SecurityAuditTool.Core.Models
{
    /// <summary>
    /// Results of a security scan
    /// </summary>
    public class ScanResult
    {
        public Guid Id { get; set; }
        public Guid ScanConfigurationId { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public ScanStatus Status { get; set; }
        public List<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();
        public ScanSummary Summary { get; set; } = new ScanSummary();
        public string ErrorMessage { get; set; }
        public string ScanOutput { get; set; }
    }

    public enum ScanStatus
    {
        Pending,
        InProgress,
        Completed,
        Failed,
        Cancelled
    }

    public class ScanSummary
    {
        public int TotalVulnerabilities { get; set; }
        public int CriticalVulnerabilities { get; set; }
        public int HighVulnerabilities { get; set; }
        public int MediumVulnerabilities { get; set; }
        public int LowVulnerabilities { get; set; }
        public double RiskScore { get; set; }
        public bool ComplianceStatus { get; set; }
        public List<string> FailedComplianceChecks { get; set; } = new List<string>();
        public List<string> PassedComplianceChecks { get; set; } = new List<string>();
        
        public int CalculateRiskScore()
        {
            // A simple risk score calculation - can be refined with more sophisticated algorithms
            return (CriticalVulnerabilities * 10) + 
                   (HighVulnerabilities * 5) + 
                   (MediumVulnerabilities * 2) + 
                   LowVulnerabilities;
        }
    }
} 