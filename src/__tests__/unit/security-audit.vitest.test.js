// @vitest-environment node

import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, it, expect, beforeEach, afterEach, vi } from '../setup/vitest-imports.js';
import { parseVulnerabilities, isValidAuditData } from '../../../scripts/vulnerability-parser.js';
import { applySeverityPolicy } from '../../../scripts/security-audit.js';
import { SECURITY_CONFIG } from '../../../scripts/security-config.js';

const createAdvisory = (severity = 'critical', overrides = {}) => ({
  id: 1000001,
  module_name: 'example-package',
  severity,
  title: 'Synthetic advisory',
  overview: 'Synthetic pnpm 8 fixture',
  cves: ['CVE-2024-0001'],
  vulnerable_versions: '<2.0.0',
  patched_versions: '>=2.0.0',
  findings: [{ version: '1.0.0', paths: ['. > example-package@1.0.0'] }],
  ...overrides,
});

const createAudit = (...advisories) => {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const advisory of advisories) counts[advisory.severity]++;
  return {
    actions: [],
    advisories: Object.fromEntries(advisories.map((advisory) => [advisory.id, advisory])),
    muted: [],
    metadata: { vulnerabilities: counts, totalDependencies: advisories.length },
  };
};

describe('pnpm audit parsing', () => {
  it('normalizes the pnpm 8 advisory envelope with stable IDs and report details', () => {
    const audit = createAudit(createAdvisory());
    const vulnerabilities = parseVulnerabilities(JSON.stringify(audit));
    expect(vulnerabilities).toEqual([
      expect.objectContaining({
        id: '1000001',
        package: 'example-package',
        severity: 'critical',
        title: 'Synthetic advisory',
        description: 'Synthetic pnpm 8 fixture',
        cves: ['CVE-2024-0001'],
        range: '<2.0.0',
        nodes: ['. > example-package@1.0.0'],
        fixAvailable: true,
      }),
    ]);
    expect(parseVulnerabilities(audit)).toEqual(vulnerabilities);
    expect(isValidAuditData(audit)).toBe(true);
  });

  it('keeps separate advisories for the same package', () => {
    const audit = createAudit(createAdvisory(), createAdvisory('high', { id: 1000002 }));
    expect(parseVulnerabilities(audit).map((vulnerability) => vulnerability.id)).toEqual([
      '1000001',
      '1000002',
    ]);
  });

  it('uses the advisory map key when the advisory has no ID', () => {
    const audit = createAudit(createAdvisory());
    delete audit.advisories[1000001].id;
    expect(parseVulnerabilities(audit)[0].id).toBe('1000001');
  });

  it('recognizes the pnpm no-fix sentinel', () => {
    const audit = createAudit(createAdvisory('high', { patched_versions: '<0.0.0' }));
    expect(parseVulnerabilities(audit)[0].fixAvailable).toBe(false);
  });

  it('accepts a complete clean pnpm report', () => {
    expect(parseVulnerabilities(createAudit())).toEqual([]);
    expect(isValidAuditData(createAudit())).toBe(true);
  });

  it('does not equate metadata occurrence counts with the number of unique advisories', () => {
    const audit = createAudit(createAdvisory('high'));
    audit.metadata.vulnerabilities.high = 3;
    expect(parseVulnerabilities(audit)).toHaveLength(1);
  });

  it('preserves the supported package-keyed format with stable package IDs', () => {
    const audit = { vulnerabilities: { 'example-package': { severity: 'high', via: [] } } };
    expect(parseVulnerabilities(audit)).toEqual([
      expect.objectContaining({
        id: 'example-package',
        package: 'example-package',
        severity: 'high',
      }),
    ]);
    expect(parseVulnerabilities({ vulnerabilities: {} })).toEqual([]);
  });

  it.each([
    null,
    [],
    {},
    { metadata: { vulnerabilities: { critical: 1 } } },
    { error: { code: 'ERR_PNPM_AUDIT_BAD_RESPONSE', message: 'Registry unavailable' } },
    { ...createAudit(), error: { message: 'Partial result' } },
    { ...createAudit(), vulnerabilities: {} },
    { advisories: {} },
    { advisories: [] },
    { vulnerabilities: [] },
    { auditReportVersion: 3, vulnerabilities: {} },
    { ...createAudit(), auditReportVersion: 3 },
    { vulnerabilities: { broken: null } },
    { vulnerabilities: { broken: {} } },
    { vulnerabilities: { broken: { severity: 'unknown' } } },
    { ...createAudit(createAdvisory()), advisories: {} },
    { ...createAudit(), advisories: { 1000001: null } },
    { ...createAudit(), advisories: { 1000001: createAdvisory('critical', { module_name: '' }) } },
    { ...createAudit(), advisories: { 1000001: createAdvisory('urgent') } },
    { ...createAudit(), metadata: { vulnerabilities: { critical: -1 } } },
    { ...createAudit(), metadata: { vulnerabilities: { critical: '0' } } },
  ])('rejects malformed, failed, or unsupported audit data: %j', (audit) => {
    expect(() => parseVulnerabilities(audit)).toThrow('Failed to parse vulnerability data');
    expect(isValidAuditData(audit)).toBe(false);
  });

  it('rejects a summary whose high findings are absent even when lower findings remain', () => {
    const audit = createAudit(createAdvisory('low'));
    audit.metadata.vulnerabilities.high = 1;
    expect(() => parseVulnerabilities(audit)).toThrow('does not match high');
  });

  it('validates severity counts in the package-keyed format, including npm totals', () => {
    const audit = {
      auditReportVersion: 2,
      vulnerabilities: { 'example-package': { severity: 'low' } },
      metadata: {
        vulnerabilities: { info: 0, low: 1, moderate: 0, high: 0, critical: 0, total: 1 },
      },
    };
    expect(parseVulnerabilities(audit)).toHaveLength(1);
    audit.metadata.vulnerabilities.high = 1;
    audit.metadata.vulnerabilities.total = 2;
    expect(() => parseVulnerabilities(audit)).toThrow('does not match high');
  });

  it.each([-1, '0', { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 1 }])(
    'rejects malformed package-map summaries: %j',
    (counts) => {
      expect(() =>
        parseVulnerabilities({ vulnerabilities: {}, metadata: { vulnerabilities: counts } })
      ).toThrow();
    }
  );

  it('rejects truncated JSON', () => {
    expect(() => parseVulnerabilities('{"advisories":')).toThrow();
  });
});

describe('advisory severity and temporary exceptions', () => {
  let originalAllowList;

  beforeEach(() => {
    originalAllowList = SECURITY_CONFIG.vulnerability.allowList;
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-15T00:00:00.000Z'));
  });

  afterEach(() => {
    SECURITY_CONFIG.vulnerability.allowList = originalAllowList;
    vi.useRealTimers();
  });

  it.each([
    ['critical', 1],
    ['high', 1],
    ['moderate', 0],
    ['low', 0],
    ['info', 0],
  ])('applies the existing policy to %s advisories', (severity, blocking) => {
    const vulnerabilities = parseVulnerabilities(createAudit(createAdvisory(severity)));
    expect(applySeverityPolicy(vulnerabilities)).toHaveLength(blocking);
  });

  it('only bypasses the matching advisory when its exception has not expired', () => {
    SECURITY_CONFIG.vulnerability.allowList = [
      { id: '1000001', reason: 'Temporary test exception', expires: '2026-01-16' },
    ];
    const vulnerabilities = parseVulnerabilities(
      createAudit(createAdvisory(), createAdvisory('critical', { id: 1000002 }))
    );
    expect(applySeverityPolicy(vulnerabilities).map((vulnerability) => vulnerability.id)).toEqual([
      '1000002',
    ]);
  });

  it.each(['2026-01-14', '2026-01-15', '2026-02-30', 'invalid', '', undefined])(
    'does not bypass an expired or malformed exception: %s',
    (expires) => {
      SECURITY_CONFIG.vulnerability.allowList = [
        { id: '1000001', reason: 'Temporary test exception', expires },
      ];
      expect(applySeverityPolicy(parseVulnerabilities(createAudit(createAdvisory())))).toHaveLength(
        1
      );
    }
  );
});

describe('offline security audit CLI', () => {
  let directory;
  const script = fileURLToPath(new URL('../../../scripts/security-audit.js', import.meta.url));

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), 'timeismoney-audit-'));
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  const runAudit = (content) => {
    writeFileSync(join(directory, 'audit-results.json'), content);
    return spawnSync(process.execPath, [script], { cwd: directory, encoding: 'utf8' });
  };

  it.each(['critical', 'high'])(
    'fails on a pnpm 8 %s advisory and writes failure artifacts',
    (severity) => {
      const result = runAudit(JSON.stringify(createAudit(createAdvisory(severity))));
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(result.stdout).toContain('Parsed 1 vulnerabilities');
      expect(result.stdout).not.toContain('Security audit passed');
      expect(
        JSON.parse(readFileSync(join(directory, 'critical-vulnerabilities.json'), 'utf8'))
      ).toMatchObject({
        policyViolation: true,
        criticalCount: 1,
        vulnerabilities: [expect.objectContaining({ id: '1000001', severity })],
      });
      expect(readFileSync(join(directory, 'security-report.md'), 'utf8')).toContain('❌ FAILED');
    }
  );

  it.each([[[]], [[createAdvisory('moderate')]]])(
    'passes clean or below-threshold results: %j',
    (advisories) => {
      const result = runAudit(JSON.stringify(createAudit(...advisories)));
      expect(result.status).toBe(0);
      expect(existsSync(join(directory, 'critical-vulnerabilities.json'))).toBe(false);
      expect(readFileSync(join(directory, 'security-report.md'), 'utf8')).toContain('✅ PASSED');
    }
  );

  it.each(['', '{"advisories":', '{}', '{"error":{"code":"ERR_PNPM_AUDIT_BAD_RESPONSE"}}'])(
    'fails without reporting a clean audit on invalid input: %j',
    (content) => {
      const result = runAudit(content);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('Security audit failed');
      expect(result.stdout).not.toContain('Total vulnerabilities found: 0');
      expect(existsSync(join(directory, 'security-report.md'))).toBe(false);
    }
  );

  it('fails if the audit result file is missing', () => {
    const result = spawnSync(process.execPath, [script], { cwd: directory, encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Audit results file not found');
  });
});
