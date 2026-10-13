/**
 * Unit tests for the security audit system
 * Tests audit script, parser, and policy logic using mock vulnerability data
 */

/* eslint-disable no-console */

// Import vi separately for mocking (required for vi.mock timing)
// eslint-disable-next-line no-restricted-imports
import { vi } from 'vitest';

// Use standardized fs/promises mock pattern
vi.mock('fs/promises', () => {
  const mockFunctions = {
    readFile: vi.fn(() => Promise.resolve('{"vulnerabilities": []}')),
    writeFile: vi.fn(() => Promise.resolve()),
    access: vi.fn(() => Promise.resolve()),
    constants: {
      F_OK: 0,
      R_OK: 4,
      W_OK: 2,
      X_OK: 1,
    },
  };
  return {
    default: mockFunctions,
    ...mockFunctions,
  };
});

import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  resetTestMocks,
} from '../setup/vitest-imports.js';

// Import modules after mocking
import { readFile, writeFile, access } from 'fs/promises';

// Wrap imported functions with vi.mocked for proper mock access
const mockedAccess = vi.mocked(access);
const mockedReadFile = vi.mocked(readFile);
const mockedWriteFile = vi.mocked(writeFile);
import {
  readAuditResults,
  applySeverityPolicy,
  createCriticalVulnerabilitiesFile,
  main,
} from '../../../scripts/security-audit.js';
import { SECURITY_CONFIG } from '../../../scripts/security-config.js';

describe('Security Audit System', () => {
  beforeEach(() => {
    resetTestMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2024-01-01T00:00:00.000Z'));

    // Mock console methods
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    // Mock process.exit to prevent actual exits during tests
    vi.spyOn(process, 'exit').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  // Mock audit data for testing
  const createMockAuditData = (vulnerabilities = {}) => ({
    auditReportVersion: 2,
    vulnerabilities,
    metadata: {
      vulnerabilities: Object.keys(vulnerabilities).length,
      dependencies: 150,
      devDependencies: 75,
      optionalDependencies: 2,
    },
  });

  const createMockVulnerability = (severity, overrides = {}) => ({
    severity,
    title: `Mock ${severity} vulnerability`,
    description: `A ${severity} severity vulnerability for testing`,
    range: '*',
    nodes: ['node_modules/mock-package'],
    fixAvailable: true,
    isDirect: false,
    effects: [],
    via: [
      {
        source: 'mock-source',
        name: 'mock-package',
        dependency: 'mock-package',
        title: `Mock ${severity} vulnerability`,
        url: 'https://example.com/advisory',
        severity,
        cwe: ['CWE-123'],
        cvss: { score: severity === 'critical' ? 9.5 : severity === 'high' ? 7.5 : 4.5 },
      },
    ],
    ...overrides,
  });

  describe('readAuditResults', () => {
    it('should read and parse valid audit results', async () => {
      const mockAuditData = createMockAuditData({
        'mock-package': createMockVulnerability('high'),
      });

      mockedAccess.mockResolvedValue();
      mockedReadFile.mockResolvedValue(JSON.stringify(mockAuditData));

      const result = await readAuditResults();

      expect(mockedAccess).toHaveBeenCalledWith('audit-results.json', 4); // F_OK | R_OK
      expect(mockedReadFile).toHaveBeenCalledWith('audit-results.json', 'utf-8');
      expect(result).toEqual(mockAuditData);
    });

    it('should throw error when audit results file not found', async () => {
      const error = new Error('File not found');
      error.code = 'ENOENT';
      mockedAccess.mockRejectedValue(error);

      await expect(readAuditResults()).rejects.toThrow(
        'Audit results file not found: audit-results.json'
      );
    });

    it('should throw error when audit data is invalid JSON', async () => {
      mockedAccess.mockResolvedValue();
      mockedReadFile.mockResolvedValue('invalid json');

      await expect(readAuditResults()).rejects.toThrow('Failed to read audit results:');
    });

    it('should accept audit data with empty vulnerabilities', async () => {
      const mockAuditData = createMockAuditData({});

      mockedAccess.mockResolvedValue();
      mockedReadFile.mockResolvedValue(JSON.stringify(mockAuditData));

      const result = await readAuditResults();
      expect(result).toEqual(mockAuditData);
    });
  });

  describe('applySeverityPolicy', () => {
    it('should filter vulnerabilities by severity policy', () => {
      const vulnerabilities = [
        { id: '1', severity: 'critical', package: 'pkg1' },
        { id: '2', severity: 'high', package: 'pkg2' },
        { id: '3', severity: 'medium', package: 'pkg3' },
        { id: '4', severity: 'low', package: 'pkg4' },
      ];

      const result = applySeverityPolicy(vulnerabilities);

      // Should only include critical and high severity (from SECURITY_CONFIG.failOnSeverity)
      expect(result).toHaveLength(2);
      expect(result[0].severity).toBe('critical');
      expect(result[1].severity).toBe('high');
    });

    it('should return empty array for invalid input', () => {
      expect(applySeverityPolicy(null)).toEqual([]);
      expect(applySeverityPolicy(undefined)).toEqual([]);
      expect(applySeverityPolicy('not an array')).toEqual([]);
    });

    it('should handle empty vulnerabilities array', () => {
      const result = applySeverityPolicy([]);
      expect(result).toEqual([]);
    });

    it('should filter out vulnerabilities in allowList', () => {
      // Store original allowList to restore later
      const originalAllowList = [...SECURITY_CONFIG.vulnerability.allowList];

      // Temporarily modify the allowList
      SECURITY_CONFIG.vulnerability.allowList = [
        { id: '1', reason: 'False positive', expires: '2024-12-31' },
        { id: '3', reason: 'Risk accepted', expires: '2024-06-30' },
      ];

      const vulnerabilities = [
        { id: '1', severity: 'critical', package: 'pkg1', title: 'Critical issue' },
        { id: '2', severity: 'high', package: 'pkg2', title: 'High issue' },
        { id: '3', severity: 'critical', package: 'pkg3', title: 'Another critical' },
        { id: '4', severity: 'medium', package: 'pkg4', title: 'Medium issue' },
      ];

      const result = applySeverityPolicy(vulnerabilities);

      // Should only include ID '2' (high severity, not in allowList)
      // IDs '1' and '3' are in allowList and should be filtered out
      // ID '4' is medium severity and excluded by severity policy
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('2');
      expect(result[0].severity).toBe('high');

      // Restore original allowList
      SECURITY_CONFIG.vulnerability.allowList = originalAllowList;
    });

    it('should work correctly when allowList is empty', () => {
      const vulnerabilities = [
        { id: '1', severity: 'critical', package: 'pkg1' },
        { id: '2', severity: 'high', package: 'pkg2' },
        { id: '3', severity: 'medium', package: 'pkg3' },
      ];

      const result = applySeverityPolicy(vulnerabilities);

      // Should include all critical and high severity vulnerabilities
      expect(result).toHaveLength(2);
      expect(result[0].severity).toBe('critical');
      expect(result[1].severity).toBe('high');
    });

    it('should work correctly when allowList is undefined or null', () => {
      // Store original allowList to restore later
      const originalAllowList = SECURITY_CONFIG.vulnerability.allowList;

      // Temporarily set allowList to null
      SECURITY_CONFIG.vulnerability.allowList = null;

      const vulnerabilities = [
        { id: '1', severity: 'critical', package: 'pkg1' },
        { id: '2', severity: 'high', package: 'pkg2' },
      ];

      const result = applySeverityPolicy(vulnerabilities);

      expect(result).toHaveLength(2);

      // Restore original allowList
      SECURITY_CONFIG.vulnerability.allowList = originalAllowList;
    });

    it('should handle allowList with non-matching IDs correctly', () => {
      // Store original allowList to restore later
      const originalAllowList = [...SECURITY_CONFIG.vulnerability.allowList];

      // Temporarily modify the allowList with non-matching IDs
      SECURITY_CONFIG.vulnerability.allowList = [
        { id: 'non-existent-1', reason: 'Test', expires: '2024-12-31' },
        { id: 'non-existent-2', reason: 'Test', expires: '2024-12-31' },
      ];

      const vulnerabilities = [
        { id: '1', severity: 'critical', package: 'pkg1' },
        { id: '2', severity: 'high', package: 'pkg2' },
      ];

      const result = applySeverityPolicy(vulnerabilities);

      // All vulnerabilities should be included since none match allowList
      expect(result).toHaveLength(2);

      // Restore original allowList
      SECURITY_CONFIG.vulnerability.allowList = originalAllowList;
    });

    it('should filter all vulnerabilities if all are in allowList', () => {
      // Store original allowList to restore later
      const originalAllowList = [...SECURITY_CONFIG.vulnerability.allowList];

      // Temporarily modify the allowList to include all test vulnerabilities
      SECURITY_CONFIG.vulnerability.allowList = [
        { id: '1', reason: 'False positive', expires: '2024-12-31' },
        { id: '2', reason: 'Risk accepted', expires: '2024-12-31' },
      ];

      const vulnerabilities = [
        { id: '1', severity: 'critical', package: 'pkg1' },
        { id: '2', severity: 'high', package: 'pkg2' },
      ];

      const result = applySeverityPolicy(vulnerabilities);

      // All vulnerabilities should be filtered out
      expect(result).toHaveLength(0);

      // Restore original allowList
      SECURITY_CONFIG.vulnerability.allowList = originalAllowList;
    });
  });

  describe('createCriticalVulnerabilitiesFile', () => {
    it('should create critical vulnerabilities file with correct structure', async () => {
      const criticalVulns = [
        { id: '1', severity: 'critical', package: 'pkg1', title: 'Critical issue' },
        { id: '2', severity: 'high', package: 'pkg2', title: 'High issue' },
      ];

      mockedWriteFile.mockResolvedValue();

      await createCriticalVulnerabilitiesFile(criticalVulns);

      expect(mockedWriteFile).toHaveBeenCalledWith(
        'critical-vulnerabilities.json',
        expect.any(String),
        'utf-8'
      );

      const [, content] = mockedWriteFile.mock.calls[0];
      const parsedContent = JSON.parse(content);

      expect(parsedContent).toMatchObject({
        policyViolation: true,
        criticalCount: 2,
        vulnerabilities: criticalVulns,
        summary: {
          total: 2,
          bySeverity: {
            critical: 1,
            high: 1,
          },
          uniquePackages: 2,
        },
      });
      expect(parsedContent.timestamp).toBeDefined();
      expect(parsedContent.failOnSeverity).toEqual(['critical', 'high']);
    });

    it('should throw error when file write fails', async () => {
      const criticalVulns = [
        { id: '1', severity: 'critical', package: 'pkg1', title: 'Critical issue' },
      ];

      mockedWriteFile.mockRejectedValue(new Error('Write permission denied'));

      await expect(createCriticalVulnerabilitiesFile(criticalVulns)).rejects.toThrow(
        'Failed to create critical vulnerabilities file: Write permission denied'
      );
    });
  });

  describe('main audit workflow', () => {
    it('should complete successful audit with no critical vulnerabilities', async () => {
      const mockAuditData = createMockAuditData({
        'medium-pkg': createMockVulnerability('medium'),
        'low-pkg': createMockVulnerability('low'),
      });

      mockedAccess.mockResolvedValue();
      mockedReadFile.mockResolvedValue(JSON.stringify(mockAuditData));

      await main();

      expect(console.log).toHaveBeenCalledWith('🔍 Starting security audit...');
      expect(console.log).toHaveBeenCalledWith('📋 Parsed 2 vulnerabilities from audit results');
      expect(console.log).toHaveBeenCalledWith('🔍 Security audit completed');
      expect(console.log).toHaveBeenCalledWith(
        '✅ All vulnerabilities are below the failure threshold'
      );
      expect(console.log).toHaveBeenCalledWith(
        '🎉 Security audit passed - no critical vulnerabilities detected'
      );
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it('should fail audit with critical vulnerabilities', async () => {
      const mockAuditData = createMockAuditData({
        'critical-pkg': createMockVulnerability('critical'),
        'high-pkg': createMockVulnerability('high'),
        'medium-pkg': createMockVulnerability('medium'),
      });

      mockedAccess.mockResolvedValue();
      mockedReadFile.mockResolvedValue(JSON.stringify(mockAuditData));
      mockedWriteFile.mockResolvedValue();

      await main();

      expect(console.log).toHaveBeenCalledWith('🔍 Starting security audit...');
      expect(console.log).toHaveBeenCalledWith('📋 Parsed 3 vulnerabilities from audit results');
      expect(console.log).toHaveBeenCalledWith('⚠️  Critical vulnerabilities: 2');
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Critical vulnerabilities detected!')
      );
      expect(mockedWriteFile).toHaveBeenCalledWith(
        'critical-vulnerabilities.json',
        expect.any(String),
        'utf-8'
      );
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should handle audit with no vulnerabilities', async () => {
      const mockAuditData = createMockAuditData({});

      mockedAccess.mockResolvedValue();
      mockedReadFile.mockResolvedValue(JSON.stringify(mockAuditData));

      await main();

      expect(console.log).toHaveBeenCalledWith('📋 Parsed 0 vulnerabilities from audit results');
      expect(console.log).toHaveBeenCalledWith('📊 Total vulnerabilities found: 0');
      expect(console.log).toHaveBeenCalledWith('⚠️  Critical vulnerabilities: 0');
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it('should handle file read errors gracefully', async () => {
      const error = new Error('File not found');
      error.code = 'ENOENT';
      mockedAccess.mockRejectedValue(error);

      await main();

      expect(console.error).toHaveBeenCalledWith(
        '❌ Security audit failed:',
        'Audit results file not found: audit-results.json'
      );
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should log detailed vulnerability breakdown', async () => {
      const mockAuditData = createMockAuditData({
        'critical-pkg1': createMockVulnerability('critical'),
        'critical-pkg2': createMockVulnerability('critical'),
        'high-pkg1': createMockVulnerability('high'),
        'medium-pkg1': createMockVulnerability('medium'),
        'low-pkg1': createMockVulnerability('low'),
      });

      mockedAccess.mockResolvedValue();
      mockedReadFile.mockResolvedValue(JSON.stringify(mockAuditData));
      mockedWriteFile.mockResolvedValue();

      await main();

      expect(console.log).toHaveBeenCalledWith('📊 Total vulnerabilities found: 5');
      expect(console.log).toHaveBeenCalledWith('📈 Breakdown by severity:');
      expect(console.log).toHaveBeenCalledWith('   🔴 critical: 2');
      expect(console.log).toHaveBeenCalledWith('   🟠 high: 1');
      expect(console.log).toHaveBeenCalledWith('   🟡 medium: 1');
      expect(console.log).toHaveBeenCalledWith('   🟡 low: 1');
      expect(console.log).toHaveBeenCalledWith('🎯 Policy threshold: critical, high');
      expect(console.log).toHaveBeenCalledWith('⚠️  Critical vulnerabilities: 3');
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle malformed vulnerability data gracefully', async () => {
      const mockAuditData = {
        auditReportVersion: 2,
        vulnerabilities: {
          'malformed-pkg': null, // Malformed vulnerability
        },
        metadata: { vulnerabilities: 1, dependencies: 1 },
      };

      mockedAccess.mockResolvedValue();
      mockedReadFile.mockResolvedValue(JSON.stringify(mockAuditData));

      await main();

      // Malformed findings must fail closed instead of reporting a clean audit.
      expect(process.exit).toHaveBeenCalledWith(1);
      expect(process.exit).not.toHaveBeenCalledWith(0);
    });
  });
});
