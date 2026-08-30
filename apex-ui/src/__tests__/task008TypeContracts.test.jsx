import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, extname, join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { WS_URL } from '../config/api';
import { FORGE_UI_VERSION } from '../App';
import {
  DASHBOARD_API,
  DASHBOARD_API_BACKEND_SHA256,
  DASHBOARD_API_BACKEND_SOURCE,
  DASHBOARD_API_ROUTES,
} from '../generated/dashboard-api';


const repositoryRoot = existsSync(join(process.cwd(), 'common/dashboard/server.py'))
  ? resolve(process.cwd())
  : resolve(process.cwd(), '..');
const generatorPath = join(repositoryRoot, 'scripts/generate_frontend_contracts.py');
const auditGatePath = join(repositoryRoot, 'apex-ui/scripts/verify-npm-audit.mjs');
const frontendRoot = join(repositoryRoot, 'apex-ui');
const typecheckExtensions = new Set(['.js', '.jsx', '.mjs', '.ts', '.tsx']);
const typecheckExcludedDirectories = new Set(['build', 'dist', 'node_modules']);
const generatedPaths = [
  'common/dashboard/server.py',
  'contracts/dashboard-api.json',
  'apex-ui/src/generated/dashboard-api.ts',
];

const copyContractFixture = () => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'forge-dashboard-contract-'));
  for (const relativePath of generatedPaths) {
    const destination = join(fixtureRoot, relativePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(repositoryRoot, relativePath), destination);
  }
  return fixtureRoot;
};

const runGeneratorCheck = (fixtureRoot) => spawnSync(
  process.env.PYTHON || 'python',
  [generatorPath, '--root', fixtureRoot, '--check'],
  { cwd: repositoryRoot, encoding: 'utf8' },
);

const reviewedAuditReport = () => ({
  auditReportVersion: 2,
  vulnerabilities: {
    'react-router': {
      name: 'react-router',
      severity: 'high',
      isDirect: false,
      via: [{
        source: 1124282,
        name: 'react-router',
        dependency: 'react-router',
        title: 'React Router: RSC Mode CSRF Bypass Allows Action Execution Before 400 Response',
        url: 'https://github.com/advisories/GHSA-qwww-vcr4-c8h2',
        severity: 'high',
        cwe: ['CWE-352'],
        range: '>=7.12.0 <8.3.0',
      }],
      effects: ['react-router-dom'],
      range: '7.12.0 - 8.2.0',
      nodes: ['node_modules/react-router'],
    },
    'react-router-dom': {
      name: 'react-router-dom',
      severity: 'high',
      isDirect: true,
      via: ['react-router'],
      effects: [],
      range: '>=7.12.0-pre.0',
      nodes: ['node_modules/react-router-dom'],
    },
  },
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 2,
      critical: 0,
      total: 2,
    },
  },
});

const cleanAuditReport = () => ({
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
      total: 0,
    },
  },
});

const createAuditFixture = () => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'forge-npm-audit-'));
  for (const relativePath of [
    'apex-ui/package.json',
    'apex-ui/package-lock.json',
    'apex-ui/config/npm-audit-exceptions.json',
  ]) {
    const fixturePath = relativePath.replace(/^apex-ui\//, '');
    const destination = join(fixtureRoot, fixturePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(repositoryRoot, relativePath), destination);
  }
  mkdirSync(join(fixtureRoot, 'src'), { recursive: true });
  writeFileSync(
    join(fixtureRoot, 'src/main.jsx'),
    [
      "import { BrowserRouter } from 'react-router-dom';",
      'export const Root = ({ children }) => <BrowserRouter>{children}</BrowserRouter>;',
      '',
    ].join('\n'),
    'utf8',
  );
  writeFileSync(
    join(fixtureRoot, 'src/App.jsx'),
    [
      "import { Routes, Route } from 'react-router-dom';",
      "export const App = () => <Routes><Route path='/fixture' element={null} /></Routes>;",
      '',
    ].join('\n'),
    'utf8',
  );
  const auditPath = join(fixtureRoot, 'audit.json');
  writeFileSync(auditPath, JSON.stringify(reviewedAuditReport()), 'utf8');
  return { fixtureRoot, auditPath };
};

const collectFrontendTypecheckSources = (root) => {
  const sources = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && typecheckExcludedDirectories.has(entry.name)) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && typecheckExtensions.has(extname(entry.name))) {
        sources.push(realpathSync(path));
      }
    }
  };
  visit(root);
  return sources.sort();
};

const createTypecheckFixture = () => {
  const fixtureRoot = mkdtempSync(join(tmpdir(), 'forge-frontend-typecheck-'));
  for (const relativePath of [
    'package.json',
    'tsconfig.json',
    'src/generated/dashboard-api.ts',
  ]) {
    const destination = join(fixtureRoot, relativePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(frontendRoot, relativePath), destination);
  }
  symlinkSync(join(frontendRoot, 'node_modules'), join(fixtureRoot, 'node_modules'), 'dir');
  return fixtureRoot;
};

const runProjectTypecheck = (fixtureRoot) => {
  const npmExecPath = process.env.npm_execpath;
  const executable = npmExecPath ? process.execPath : 'npm';
  const prefix = npmExecPath ? [npmExecPath] : [];
  return spawnSync(executable, [...prefix, 'run', 'typecheck'], {
    cwd: fixtureRoot,
    encoding: 'utf8',
  });
};

const runAuditGate = ({ fixtureRoot, auditPath }, asOf = '2026-08-03') => spawnSync(
  process.execPath,
  [
    auditGatePath,
    '--project-root',
    fixtureRoot,
    '--audit-json',
    auditPath,
    '--as-of',
    asOf,
  ],
  { cwd: repositoryRoot, encoding: 'utf8' },
);


describe('Task 008 frontend type and generated-contract gates', () => {
  it('includes every frontend JavaScript and TypeScript source in the checked program', () => {
    const typecheck = spawnSync(
      join(frontendRoot, 'node_modules/.bin/tsc'),
      [
        '--project',
        join(frontendRoot, 'tsconfig.json'),
        '--noEmit',
        '--pretty',
        'false',
        '--listFilesOnly',
      ],
      { cwd: frontendRoot, encoding: 'utf8' },
    );
    expect(typecheck.status, `${typecheck.stdout}${typecheck.stderr}`).toBe(0);

    const included = new Set(
      typecheck.stdout
        .split(/\r?\n/)
        .filter(path => path && existsSync(path))
        .map(path => realpathSync(path)),
    );
    const relevant = collectFrontendTypecheckSources(frontendRoot);
    const missing = relevant.filter(path => !included.has(path));

    expect(relevant).toContain(realpathSync(auditGatePath));
    expect(missing).toEqual([]);
  });

  it('uses backend-derived endpoint truth in authentication and WebSocket configuration', () => {
    expect(DASHBOARD_API_BACKEND_SOURCE).toBe('common/dashboard/server.py');
    expect(DASHBOARD_API_BACKEND_SHA256).toMatch(/^[a-f0-9]{64}$/);
    expect(DASHBOARD_API.authLogin).toEqual({
      method: 'POST',
      path: '/api/v1/auth/login',
    });
    expect(DASHBOARD_API.websocket).toEqual({
      method: 'WS',
      path: '/ws/dashboard',
    });
    expect(DASHBOARD_API_ROUTES).toContainEqual(DASHBOARD_API.authLogin);
    expect(DASHBOARD_API_ROUTES).toContainEqual(DASHBOARD_API.websocket);
    expect(WS_URL.endsWith(DASHBOARD_API.websocket.path)).toBe(true);
    expect(DASHBOARD_API_ROUTES).toHaveLength(70);
  });

  it('renders the canonical repository version through the Vite build constant', () => {
    const canonicalVersion = readFileSync(join(repositoryRoot, 'VERSION'), 'utf8').trim();
    expect(canonicalVersion).toMatch(/^\d+\.\d+\.\d+$/);
    expect(FORGE_UI_VERSION).toBe(canonicalVersion);
  });

  it('consumes generated endpoint constants in runtime UI call sites', () => {
    const requiredUses = {
      'apex-ui/src/App.jsx': [
        'DASHBOARD_API.authLogin',
        'DASHBOARD_API.authSsoConfig',
      ],
      'apex-ui/src/config/api.js': ['DASHBOARD_API.websocket'],
      'apex-ui/src/pages/AutomatedScans.jsx': [
        'DASHBOARD_API.health',
        'DASHBOARD_API.startScan',
        'DASHBOARD_API.deleteScan',
      ],
      'apex-ui/src/pages/ScanBuilder.jsx': [
        'DASHBOARD_API.launchScan',
        'DASHBOARD_API.scanTemplates',
      ],
    };
    for (const [relativePath, endpointUses] of Object.entries(requiredUses)) {
      const source = readFileSync(join(repositoryRoot, relativePath), 'utf8');
      for (const endpointUse of endpointUses) expect(source).toContain(endpointUse);
    }
  });

  it('fails deterministically for generated-output and backend API drift', () => {
    const fixtureRoot = copyContractFixture();
    try {
      expect(runGeneratorCheck(fixtureRoot).status).toBe(0);

      const generatedTypePath = join(
        fixtureRoot,
        'apex-ui/src/generated/dashboard-api.ts',
      );
      appendFileSync(generatedTypePath, '// seeded generated-output drift\n', 'utf8');
      const outputDrift = runGeneratorCheck(fixtureRoot);
      expect(outputDrift.status).toBe(1);
      expect(outputDrift.stdout).toContain(
        'stale generated contract: apex-ui/src/generated/dashboard-api.ts',
      );

      copyFileSync(
        join(repositoryRoot, 'apex-ui/src/generated/dashboard-api.ts'),
        generatedTypePath,
      );
      const backendPath = join(fixtureRoot, 'common/dashboard/server.py');
      const backendSource = readFileSync(backendPath, 'utf8');
      writeFileSync(
        backendPath,
        backendSource.replace(
          '("POST", "/api/v1/auth/login")',
          '("POST", "/api/v1/auth/login-seeded-drift")',
        ),
        'utf8',
      );
      const backendDrift = runGeneratorCheck(fixtureRoot);
      expect(backendDrift.status).toBe(2);
      expect(backendDrift.stdout).toContain(
        'route policy does not match decorated API routes',
      );
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it('rejects a seeded misuse of a generated endpoint method type', () => {
    const fixtureRoot = createTypecheckFixture();
    try {
      const seededTypePath = join(
        fixtureRoot,
        'src/generated/seeded-contract-error.ts',
      );
      writeFileSync(
        seededTypePath,
        [
          "import { DASHBOARD_API } from './dashboard-api';",
          'const method: "GET" = DASHBOARD_API.authLogin.method;',
          'void method;',
          '',
        ].join('\n'),
        'utf8',
      );
      const typecheck = runProjectTypecheck(fixtureRoot);
      expect(typecheck.status).not.toBe(0);
      expect(`${typecheck.stdout}${typecheck.stderr}`).toContain(
        'Type \'"POST"\' is not assignable to type \'"GET"\'',
      );
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it('accepts only the exact reviewed npm advisory in declarative SPA mode', () => {
    const fixture = createAuditFixture();
    try {
      const result = runAuditGate(fixture);
      expect(result.status).toBe(0);
      expect(result.stdout).toContain('PASS npm-audit advisory=GHSA-qwww-vcr4-c8h2');
      expect(result.stdout).toContain('mode=declarative_browser_spa');
    } finally {
      rmSync(fixture.fixtureRoot, { recursive: true, force: true });
    }
  });

  it('accepts a clean npm audit after lock-only remediation', () => {
    const fixture = createAuditFixture();
    try {
      writeFileSync(fixture.auditPath, JSON.stringify(cleanAuditReport()), 'utf8');
      rmSync(join(fixture.fixtureRoot, 'config/npm-audit-exceptions.json'));
      const result = runAuditGate(fixture);
      expect(result.status).toBe(0);
      expect(result.stdout).toContain(
        'PASS npm-audit vulnerabilities=0 disposition=NO_VULNERABILITIES',
      );
    } finally {
      rmSync(fixture.fixtureRoot, { recursive: true, force: true });
    }
  });

  it('rejects any additional npm advisory and an expired review', () => {
    const fixture = createAuditFixture();
    try {
      const report = reviewedAuditReport();
      report.vulnerabilities['react-router'].via.push({
        source: 9999999,
        name: 'react-router',
        dependency: 'react-router',
        title: 'Seeded fixture advisory',
        url: 'https://github.com/advisories/GHSA-seeded-fixture',
        severity: 'low',
        cwe: ['CWE-20'],
        range: '*',
      });
      writeFileSync(fixture.auditPath, JSON.stringify(report), 'utf8');
      const additional = runAuditGate(fixture);
      expect(additional.status).toBe(1);
      expect(additional.stderr).toContain('only react-router audit cause');

      writeFileSync(fixture.auditPath, JSON.stringify(reviewedAuditReport()), 'utf8');
      const expired = runAuditGate(fixture, '2026-09-04');
      expect(expired.status).toBe(1);
      expect(expired.stderr).toContain('exception expired on 2026-09-03');
    } finally {
      rmSync(fixture.fixtureRoot, { recursive: true, force: true });
    }
  });

  it('rejects RSC, server, or framework APIs under the non-applicability record', () => {
    const fixture = createAuditFixture();
    try {
      writeFileSync(
        join(fixture.fixtureRoot, 'src/rsc.jsx'),
        'export const unstable_RSCHydratedRouter = true;\n',
        'utf8',
      );
      const result = runAuditGate(fixture);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('RSC hydrated router is present');
    } finally {
      rmSync(fixture.fixtureRoot, { recursive: true, force: true });
    }
  });
});
