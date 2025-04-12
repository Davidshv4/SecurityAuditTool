using System.Threading.Tasks;
using SecurityAuditTool.Core.Models;

namespace SecurityAuditTool.Core.Interfaces
{
    /// <summary>
    /// Interface for report generators
    /// </summary>
    public interface IReportGenerator
    {
        /// <summary>
        /// Generates a report based on the scan result
        /// </summary>
        /// <param name="scanResult">The scan result to generate a report for</param>
        /// <param name="format">The format of the report</param>
        /// <returns>The path to the generated report</returns>
        Task<string> GenerateReportAsync(ScanResult scanResult, ReportFormat format);
    }

    public enum ReportFormat
    {
        PDF,
        HTML,
        XML,
        JSON,
        CSV
    }
} 