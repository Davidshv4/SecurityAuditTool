@echo off
echo Running Enterprise Security Audit Tool...
echo.

REM Check if .NET SDK is installed
where dotnet >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo .NET SDK is not installed. Please install .NET SDK from https://dotnet.microsoft.com/download
    echo.
    echo Simulating run without .NET SDK...
    echo.
    goto Simulate
)

REM If .NET SDK is installed, run the actual application
dotnet run --project src\Program.cs
goto End

:Simulate
echo Enterprise Security Audit Tool
echo ==============================
echo.
echo Available Scanners:
echo - Authentication & Authorization Scanner
echo   Scans for vulnerabilities related to authentication and authorization mechanisms
echo.
echo - Dependency Scanner
echo   Scans for outdated dependencies and known vulnerable packages
echo.
echo Running security scan...
echo.
echo Running Authentication & Authorization Scanner...
echo Found 4 vulnerabilities.
echo.
echo Running Dependency Scanner...
echo Found 3 vulnerabilities.
echo.
echo Scan Summary:
echo Total Vulnerabilities: 7
echo Critical Vulnerabilities: 2
echo High Vulnerabilities: 2
echo Medium Vulnerabilities: 2
echo Low Vulnerabilities: 1
echo Risk Score: 22
echo Compliance Status: Non-Compliant
echo.
echo Generating reports...
echo HTML Report: C:\Reports\SecurityReport_12345_20230325121534.html
echo PDF Report: C:\Reports\SecurityReport_12345_20230325121534.txt
echo CSV Report: C:\Reports\SecurityReport_12345_20230325121534.csv
echo.
echo Security scan completed. Press any key to exit.
pause >nul

:End 