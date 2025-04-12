using System;
using System.Collections.Generic;

namespace SecurityAuditTool.Core.Models
{
    /// <summary>
    /// Configuration for a security scan
    /// </summary>
    public class ScanConfiguration
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public List<string> TargetUrls { get; set; } = new List<string>();
        public List<string> TargetApplications { get; set; } = new List<string>();
        public bool CheckAuthentication { get; set; } = true;
        public bool CheckAuthorization { get; set; } = true;
        public bool CheckDependencies { get; set; } = true;
        public bool CheckCommonVulnerabilities { get; set; } = true;
        public bool GenerateComplianceReport { get; set; } = true;
        public AuthenticationSettings AuthenticationSettings { get; set; }
        public ScanSchedule Schedule { get; set; }
    }

    public class AuthenticationSettings
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string AuthToken { get; set; }
        public AuthenticationType AuthType { get; set; }
        public string LoginUrl { get; set; }
    }

    public enum AuthenticationType
    {
        None,
        Basic,
        OAuth,
        JWT,
        SAML,
        Custom
    }

    public class ScanSchedule
    {
        public bool IsRecurring { get; set; }
        public RecurrenceType RecurrenceType { get; set; }
        public DateTime? StartDate { get; set; }
        public DateTime? EndDate { get; set; }
        public TimeSpan? StartTime { get; set; }
    }

    public enum RecurrenceType
    {
        Daily,
        Weekly,
        Monthly
    }
} 