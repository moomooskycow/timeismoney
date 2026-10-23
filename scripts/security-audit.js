#!/usr/bin/env node

/**
 * Core security audit script for processing dependency vulnerability scan results.
 * Reads pnpm audit output, applies security policies, and creates failure artifacts when critical vulnerabilities are detected.
 *
 * @file Main security audit processing script
 */

import { readFile, writeFile, access, constants } from 'fs/promises';
import { resolve } from 'path';
import {
  parseVulnerabilities,
  isValidAuditData,
  filterBySeverity,
} from './vulnerability-parser.js';
import { SECURITY_CONFIG } from './security-config.js';

/**
 * Default file paths for audit processing
 */
const AUDIT_RESULTS_FILE = 'audit-results.json';
const CRITICAL_VULNERABILITIES_FILE = 'critical-vulnerabilities.json';
const SECURITY_REPORT_FILE = 'security-report.md';

/**
 * Reads and validates audit results from the audit-results.json file
 *
 * @returns {Promise<object>} Parsed audit data
 * @throws {Error} When file doesn't exist, is unreadable, or contains invalid data
 */
async function readAuditResults() {
  try {
    // Check if audit results file exists
    await access(AUDIT_RESULTS_FILE, constants.F_OK | constants.R_OK);

    // Read and parse the audit results
    const auditContent = await readFile(AUDIT_RESULTS_FILE, 'utf-8');
    const auditData = JSON.parse(auditContent);

    // Validate the audit data structure
    if (!isValidAuditData(auditData)) {
      throw new Error('Invalid audit data format - missing required properties');
    }

    return auditData;
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(`Audit results file not found: ${AUDIT_RESULTS_FILE}`);
    }
    if (error.code === 'EACCES') {
      throw new Error(`Cannot read audit results file: ${AUDIT_RESULTS_FILE}`);
    }
    throw new Error(`Failed to read audit results: ${error.message}`);
  }
}

/**
 * Applies security policies to filter vulnerabilities that should cause CI failure
 *
 * @param {Array<object>} vulnerabilities - Array of parsed vulnerability objects
 * @returns {Array<object>} Filtered vulnerabilities that violate security policies
 */
function applySeverityPolicy(vulnerabilities) {
  if (!Array.isArray(vulnerabilities)) {
    return [];
  }

  // Get the severity levels that should cause failures
  const { failOnSeverity, allowList } = SECURITY_CONFIG.vulnerability;

  // Filter vulnerabilities by severity threshold
  let criticalVulnerabilities = filterBySeverity(vulnerabilities, failOnSeverity);

  // Apply allowList filtering - remove any vulnerabilities that are temporarily approved
  if (allowList && allowList.length > 0) {
    criticalVulnerabilities = criticalVulnerabilities.filter((vuln) => {
      // Check if this vulnerability ID is in the allowList
      const isAllowed = allowList.some((allowed) => {
        if (allowed.id !== vuln.id || !/^\d{4}-\d{2}-\d{2}$/.test(allowed.expires)) {
          return false;
        }
        const expires = new Date(`${allowed.expires}T00:00:00.000Z`);
        // Exceptions expire at the start of the specified UTC date. Invalid dates fail closed.
        return (
          Number.isFinite(expires.getTime()) &&
          expires.toISOString().slice(0, 10) === allowed.expires &&
          expires.getTime() > Date.now()
        );
      });
      return !isAllowed;
    });
  }

  return criticalVulnerabilities;
}

/**
 * Creates the critical vulnerabilities artifact file for CI failure detection
 *
 * @param {Array<object>} criticalVulnerabilities - Array of critical vulnerability objects
 * @returns {Promise<void>}
 * @throws {Error} When file cannot be written
 */
async function createCriticalVulnerabilitiesFile(criticalVulnerabilities) {
  try {
    const outputData = {
      timestamp: new Date().toISOString(),
      policyViolation: true,
      failOnSeverity: SECURITY_CONFIG.vulnerability.failOnSeverity,
      criticalCount: criticalVulnerabilities.length,
      vulnerabilities: criticalVulnerabilities,
      summary: generateVulnerabilitySummary(criticalVulnerabilities),
    };

    const outputContent = JSON.stringify(outputData, null, 2);
    await writeFile(CRITICAL_VULNERABILITIES_FILE, outputContent, 'utf-8');

    console.error(
      `❌ Critical vulnerabilities detected! Details written to ${CRITICAL_VULNERABILITIES_FILE}`
    );
    console.error(`📊 Summary: ${criticalVulnerabilities.length} critical vulnerabilities found`);

    // Log individual vulnerabilities for immediate visibility
    criticalVulnerabilities.forEach((vuln, index) => {
      console.error(`   ${index + 1}. ${vuln.package} (${vuln.severity}): ${vuln.title}`);
    });
  } catch (error) {
    throw new Error(`Failed to create critical vulnerabilities file: ${error.message}`);
  }
}

/**
 * Generates a summary of vulnerabilities grouped by severity
 *
 * @param {Array<object>} vulnerabilities - Array of vulnerability objects
 * @returns {object} Summary object with counts by severity
 */
function generateVulnerabilitySummary(vulnerabilities) {
  const summary = {
    total: vulnerabilities.length,
    bySeverity: {},
    packages: new Set(),
  };

  vulnerabilities.forEach((vuln) => {
    const severity = vuln.severity.toLowerCase();
    summary.bySeverity[severity] = (summary.bySeverity[severity] || 0) + 1;
    summary.packages.add(vuln.package);
  });

  summary.uniquePackages = summary.packages.size;
  delete summary.packages; // Remove Set object before JSON serialization

  return summary;
}

/**
 * Logs audit completion with summary information
 *
 * @param {Array<object>} allVulnerabilities - All parsed vulnerabilities
 * @param {Array<object>} criticalVulnerabilities - Filtered critical vulnerabilities
 */
function logAuditSummary(allVulnerabilities, criticalVulnerabilities) {
  const summary = generateVulnerabilitySummary(allVulnerabilities);

  console.log('🔍 Security audit completed');
  console.log(`📊 Total vulnerabilities found: ${summary.total}`);

  if (summary.total > 0) {
    console.log('📈 Breakdown by severity:');
    Object.entries(summary.bySeverity).forEach(([severity, count]) => {
      const icon = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : '🟡';
      console.log(`   ${icon} ${severity}: ${count}`);
    });
  }

  console.log(`🎯 Policy threshold: ${SECURITY_CONFIG.vulnerability.failOnSeverity.join(', ')}`);
  console.log(`⚠️  Critical vulnerabilities: ${criticalVulnerabilities.length}`);

  if (criticalVulnerabilities.length === 0) {
    console.log('✅ All vulnerabilities are below the failure threshold');
  }
}

/**
 * Generates a human-readable markdown security report
 *
 * @param {Array<object>} allVulnerabilities - All parsed vulnerabilities
 * @param {Array<object>} criticalVulnerabilities - Filtered critical vulnerabilities
 * @returns {string} Markdown formatted security report
 */
function generateSecurityReport(allVulnerabilities, criticalVulnerabilities) {
  const timestamp = new Date().toISOString();
  const summary = generateVulnerabilitySummary(allVulnerabilities);
  const { failOnSeverity, allowList } = SECURITY_CONFIG.vulnerability;

  let report = `# Security Audit Report

**Generated:** ${timestamp}  
**Audit Status:** ${criticalVulnerabilities.length > 0 ? '❌ FAILED' : '✅ PASSED'}  
**Total Vulnerabilities:** ${summary.total}  
**Critical Vulnerabilities:** ${criticalVulnerabilities.length}

## Executive Summary

`;

  if (summary.total === 0) {
    report += `🎉 **No vulnerabilities detected** - Your dependencies are secure!

`;
  } else {
    report += `Found **${summary.total}** vulnerabilities across **${summary.uniquePackages}** packages.

`;

    if (criticalVulnerabilities.length > 0) {
      report += `⚠️  **${criticalVulnerabilities.length}** vulnerabilities exceed the failure threshold and require immediate attention.

`;
    } else {
      report += `✅ All vulnerabilities are below the failure threshold.

`;
    }
  }

  // Policy Configuration Section
  report += `## Policy Configuration

- **Failure Threshold:** ${failOnSeverity.join(', ')}
- **Maximum Age:** ${SECURITY_CONFIG.vulnerability.maxAge} days
- **Allowlist Entries:** ${allowList ? allowList.length : 0}

`;

  // Vulnerability Breakdown
  if (summary.total > 0) {
    report += `## Vulnerability Breakdown

`;

    Object.entries(summary.bySeverity).forEach(([severity, count]) => {
      const icon =
        severity === 'critical'
          ? '🔴'
          : severity === 'high'
            ? '🟠'
            : severity === 'medium'
              ? '🟡'
              : '🟢';
      const isBlocking = failOnSeverity.includes(severity);
      const status = isBlocking ? ' (Blocking)' : ' (Non-blocking)';
      report += `- **${icon} ${severity.toUpperCase()}${status}:** ${count}\n`;
    });

    report += `
`;

    // Critical Vulnerabilities Details
    if (criticalVulnerabilities.length > 0) {
      report += `## Critical Vulnerabilities (Blocking Build)

`;

      criticalVulnerabilities.forEach((vuln, index) => {
        report += `### ${index + 1}. ${vuln.package}

- **Severity:** ${vuln.severity.toUpperCase()}
- **Title:** ${vuln.title}
- **ID:** ${vuln.id || 'N/A'}
- **Fix Available:** ${vuln.fixAvailable ? 'Yes' : 'No'}

`;
      });
    }

    // Non-Critical Vulnerabilities Summary
    const nonCriticalVulns = allVulnerabilities.filter(
      (vuln) => !criticalVulnerabilities.some((critical) => critical.id === vuln.id)
    );

    if (nonCriticalVulns.length > 0) {
      report += `## Other Vulnerabilities (Non-blocking)

`;

      const nonCriticalByPackage = {};
      nonCriticalVulns.forEach((vuln) => {
        if (!nonCriticalByPackage[vuln.package]) {
          nonCriticalByPackage[vuln.package] = [];
        }
        nonCriticalByPackage[vuln.package].push(vuln);
      });

      Object.entries(nonCriticalByPackage).forEach(([packageName, vulns]) => {
        report += `- **${packageName}:** ${vulns.length} vulnerabilities (${vulns.map((v) => v.severity).join(', ')})\n`;
      });

      report += `
`;
    }
  }

  // Allowlist Section
  if (allowList && allowList.length > 0) {
    report += `## Allowlist

Configured exceptions apply only before their expiration date (00:00 UTC). Expired or invalid entries do not bypass the failure threshold:

`;

    allowList.forEach((entry, index) => {
      report += `${index + 1}. **ID:** ${entry.id}
   - **Reason:** ${entry.reason}
   - **Expires:** ${entry.expires}

`;
    });
  }

  // Recommendations Section
  report += `## Recommendations

`;

  if (criticalVulnerabilities.length > 0) {
    report += `⚠️  **Immediate Action Required:**
- Review and update packages with critical/high severity vulnerabilities
- Consider using \`pnpm update\` to update to latest secure versions
- If fixes are not available, consider adding temporary allowlist entries with expiration dates

`;
  }

  if (summary.total > 0) {
    report += `📋 **General Maintenance:**
- Regularly run \`pnpm audit\` to check for new vulnerabilities
- Keep dependencies updated to their latest secure versions
- Monitor vulnerability databases for emerging threats

`;
  }

  report += `📊 **Monitoring:**
- This report is generated on every CI run
- Download security reports from GitHub Actions artifacts
- Review allowlist entries before their expiration dates

---

*Report generated by automated security audit system*
`;

  return report;
}

/**
 * Creates the security report markdown file for CI artifact collection
 *
 * @param {Array<object>} allVulnerabilities - All parsed vulnerabilities
 * @param {Array<object>} criticalVulnerabilities - Filtered critical vulnerabilities
 * @returns {Promise<void>}
 * @throws {Error} When file cannot be written
 */
async function createSecurityReportFile(allVulnerabilities, criticalVulnerabilities) {
  try {
    const reportContent = generateSecurityReport(allVulnerabilities, criticalVulnerabilities);
    await writeFile(SECURITY_REPORT_FILE, reportContent, 'utf-8');

    console.log(`📄 Security report generated: ${SECURITY_REPORT_FILE}`);
  } catch (error) {
    throw new Error(`Failed to create security report file: ${error.message}`);
  }
}

/**
 * Main audit processing function
 * Orchestrates the entire security audit workflow
 *
 * @returns {Promise<void>}
 */
async function main() {
  try {
    console.log('🔍 Starting security audit...');

    // Read and parse audit results
    const auditData = await readAuditResults();
    const allVulnerabilities = parseVulnerabilities(auditData);

    console.log(`📋 Parsed ${allVulnerabilities.length} vulnerabilities from audit results`);

    // Apply security policies to identify critical vulnerabilities
    const criticalVulnerabilities = applySeverityPolicy(allVulnerabilities);

    // Log summary information
    logAuditSummary(allVulnerabilities, criticalVulnerabilities);

    // Always generate security report for CI artifacts (regardless of pass/fail status)
    await createSecurityReportFile(allVulnerabilities, criticalVulnerabilities);

    // If we have critical vulnerabilities, create the failure artifact and exit with error
    if (criticalVulnerabilities.length > 0) {
      await createCriticalVulnerabilitiesFile(criticalVulnerabilities);
      process.exit(1);
    }

    // No critical vulnerabilities - audit passed
    console.log('🎉 Security audit passed - no critical vulnerabilities detected');
    process.exit(0);
  } catch (error) {
    console.error('❌ Security audit failed:', error.message);
    process.exit(1);
  }
}

// Execute main function if this script is run directly
if (import.meta.url === `file://${resolve(process.argv[1])}`) {
  main();
}

export {
  readAuditResults,
  applySeverityPolicy,
  createCriticalVulnerabilitiesFile,
  generateSecurityReport,
  createSecurityReportFile,
  main,
};
