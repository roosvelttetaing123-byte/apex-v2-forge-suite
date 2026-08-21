#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const EXPECTED_PACKAGE_MANAGER = 'npm@10.8.2';
const EXPECTED_EXCEPTION = {
  id: 'FORGE-NPM-EXC-2026-001',
  disposition: 'NON_APPLICABLE',
  package: 'react-router',
  installed_version: '7.18.2',
  affected_dependent: 'react-router-dom',
  affected_dependent_version: '7.18.2',
  advisory: 'GHSA-qwww-vcr4-c8h2',
  advisory_source_id: 1124282,
  advisory_url: 'https://github.com/advisories/GHSA-qwww-vcr4-c8h2',
  advisory_range: '>=7.12.0 <8.3.0',
  severity: 'high',
  fixed_version: '8.3.0',
  owner: 'Core Security Engineering Lead',
  reviewed_on: '2026-08-03',
  expires_on: '2026-09-03',
  reason: "The advisory applies only to React Router's unstable RSC action transport. Apex UI is a client-only Vite SPA in declarative BrowserRouter library mode and uses no RSC, server, or React Router framework APIs or packages.",
};
const FORBIDDEN_PACKAGES = [
  '@react-router/cloudflare',
  '@react-router/dev',
  '@react-router/express',
  '@react-router/fs-routes',
  '@react-router/node',
  '@react-router/serve',
  '@vitejs/plugin-rsc',
  'react-server-dom-parcel',
  'react-server-dom-turbopack',
  'react-server-dom-vite',
  'react-server-dom-webpack',
  'vite-plugin-rsc',
];
/** @type {ReadonlyArray<readonly [string, RegExp]>} */
const FORBIDDEN_SOURCE_PATTERNS = [
  ['RSC hydrated router', /\bunstable_RSCHydratedRouter\b/],
  ['RSC static router', /\bunstable_RSCStaticRouter\b/],
  ['RSC call server', /\bunstable_createCallServer\b/],
  ['RSC stream', /\bunstable_getRSCStream\b/],
  ['RSC server request', /\bunstable_routeRSCServerRequest\b/],
  ['RSC development hooks', /\bunstable_setDevServerHooks\b/],
  ['server request handler', /\bcreateRequestHandler\b/],
  ['static data router', /\bcreateStatic(?:Handler|Router)\b/],
  ['static router provider', /\bStaticRouterProvider\b/],
  ['framework hydrated router', /\bHydratedRouter\b/],
  ['framework server router', /\bServerRouter\b/],
  ['React server directive', /['"]use server['"]/],
  ['React DOM server import', /react-dom\/server/],
  ['React server renderer', /\brenderTo(?:Pipeable|Readable)Stream\b/],
  ['React server package', /react-server-dom-/],
  ['React Router framework package', /@react-router\/(?:cloudflare|dev|express|fs-routes|node|serve)/],
  ['direct React Router core import', /(?:from\s+|import\s*\()\s*['"]react-router['"]/],
];
const SOURCE_EXTENSIONS = new Set(['.js', '.jsx', '.mjs', '.ts', '.tsx']);

class GateError extends Error {}

function fail(message) {
  throw new GateError(message);
}

function parseArguments(argv) {
  const parsed = { projectRoot: null, auditJson: null, asOf: null };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const value = argv[index + 1];
    if (argument === '--project-root' && value) parsed.projectRoot = value;
    else if (argument === '--audit-json' && value) parsed.auditJson = value;
    else if (argument === '--as-of' && value) parsed.asOf = value;
    else fail(`unknown or incomplete argument: ${argument}`);
    index += 1;
  }
  if (parsed.asOf && !parsed.auditJson) {
    fail('--as-of is only permitted with a deterministic --audit-json fixture');
  }
  return parsed;
}

function readJson(path, label) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    fail(`${label} is unreadable: ${error instanceof Error ? error.message : String(error)}`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function assertExactKeys(value, expectedKeys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} keys changed: expected=${expected.join(',')} actual=${actual.join(',')}`);
  }
}

function assertExactArray(value, expected, label) {
  if (!Array.isArray(value) || JSON.stringify(value) !== JSON.stringify(expected)) {
    fail(`${label} changed: expected=${JSON.stringify(expected)} actual=${JSON.stringify(value)}`);
  }
}

function validateExceptionRecord(projectRoot, asOf) {
  const path = join(projectRoot, 'config', 'npm-audit-exceptions.json');
  const config = readJson(path, 'npm audit exception record');
  assertExactKeys(config, ['schema_version', 'exceptions'], 'exception document');
  if (config.schema_version !== 'forge-npm-audit-exceptions-v1') fail('exception schema version changed');
  if (!Array.isArray(config.exceptions) || config.exceptions.length !== 1) {
    fail('exactly one npm audit exception is permitted');
  }
  const record = config.exceptions[0];
  assertExactKeys(record, Object.keys(EXPECTED_EXCEPTION), 'exception record');
  for (const [field, expected] of Object.entries(EXPECTED_EXCEPTION)) {
    if (record[field] !== expected) {
      fail(`exception field ${field} changed: expected=${JSON.stringify(expected)} actual=${JSON.stringify(record[field])}`);
    }
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(asOf)) fail(`invalid audit review date: ${asOf}`);
  if (asOf > record.expires_on) {
    fail(`npm audit exception expired on ${record.expires_on}; review date is ${asOf}`);
  }
  return record;
}

function lockPackage(lock, packageName) {
  const packageKey = `node_modules/${packageName}`;
  const entry = lock?.packages?.[packageKey];
  if (!entry || typeof entry !== 'object') fail(`package lock is missing ${packageKey}`);
  return entry;
}

function validatePinnedPackages(projectRoot, record) {
  const packageJson = readJson(join(projectRoot, 'package.json'), 'package.json');
  const lock = readJson(join(projectRoot, 'package-lock.json'), 'package-lock.json');
  if (packageJson.packageManager !== EXPECTED_PACKAGE_MANAGER) {
    fail(`packageManager must be ${EXPECTED_PACKAGE_MANAGER}`);
  }
  if (packageJson.engines?.node !== '20.19.5' || packageJson.engines?.npm !== '10.8.2') {
    fail('qualified Node/npm engines must remain exactly 20.19.5/10.8.2');
  }
  if (packageJson.scripts?.['audit:ci'] !== 'node scripts/verify-npm-audit.mjs') {
    fail('audit:ci must invoke the fail-closed npm audit verifier without fixture arguments');
  }
  if (packageJson.dependencies?.[record.affected_dependent] !== record.affected_dependent_version) {
    fail(`${record.affected_dependent} must be an exact ${record.affected_dependent_version} dependency`);
  }
  const rootLock = lock?.packages?.[''];
  if (lock.lockfileVersion !== 3 || rootLock?.dependencies?.[record.affected_dependent] !== record.affected_dependent_version) {
    fail('package lock root or lockfile version does not match the reviewed dependency');
  }
  if (lockPackage(lock, record.package).version !== record.installed_version) {
    fail(`${record.package} lock version changed from reviewed ${record.installed_version}`);
  }
  if (lockPackage(lock, record.affected_dependent).version !== record.affected_dependent_version) {
    fail(`${record.affected_dependent} lock version changed from reviewed ${record.affected_dependent_version}`);
  }
  for (const packageName of FORBIDDEN_PACKAGES) {
    const suffix = `node_modules/${packageName}`;
    if (Object.keys(lock.packages || {}).some(key => key === suffix || key.endsWith(`/${suffix}`))) {
      fail(`RSC/server/framework package is not permitted: ${packageName}`);
    }
    const declared = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.devDependencies || {}),
      ...(packageJson.optionalDependencies || {}),
    };
    if (Object.hasOwn(declared, packageName)) fail(`forbidden package is declared: ${packageName}`);
  }
  return { packageJson, lock };
}

function validateCleanAuditPackages(projectRoot) {
  const packageJson = readJson(join(projectRoot, 'package.json'), 'package.json');
  const lock = readJson(join(projectRoot, 'package-lock.json'), 'package-lock.json');
  if (packageJson.packageManager !== EXPECTED_PACKAGE_MANAGER) {
    fail(`packageManager must be ${EXPECTED_PACKAGE_MANAGER}`);
  }
  if (packageJson.engines?.node !== '20.19.5' || packageJson.engines?.npm !== '10.8.2') {
    fail('qualified Node/npm engines must remain exactly 20.19.5/10.8.2');
  }
  if (packageJson.scripts?.['audit:ci'] !== 'node scripts/verify-npm-audit.mjs') {
    fail('audit:ci must invoke the fail-closed npm audit verifier without fixture arguments');
  }
  if (lock.lockfileVersion !== 3) fail('package lock must use lockfile version 3');
  for (const packageName of FORBIDDEN_PACKAGES) {
    const suffix = `node_modules/${packageName}`;
    if (Object.keys(lock.packages || {}).some(key => key === suffix || key.endsWith(`/${suffix}`))) {
      fail(`RSC/server/framework package is not permitted: ${packageName}`);
    }
    const declared = {
      ...(packageJson.dependencies || {}),
      ...(packageJson.devDependencies || {}),
      ...(packageJson.optionalDependencies || {}),
    };
    if (Object.hasOwn(declared, packageName)) fail(`forbidden package is declared: ${packageName}`);
  }
  return packageJson;
}

function productionSources(root) {
  const collected = [];
  const visit = path => {
    for (const name of readdirSync(path)) {
      const child = join(path, name);
      const stat = statSync(child);
      if (stat.isDirectory()) {
        if (['__tests__', 'dist', 'node_modules', 'test', 'tests'].includes(name)) continue;
        visit(child);
      } else if (
        SOURCE_EXTENSIONS.has(extname(name))
        && !name.includes('.test.')
        && !name.includes('.spec.')
        && name !== 'test-setup.js'
      ) {
        collected.push(child);
      }
    }
  };
  visit(root);
  return collected.sort();
}

function validateDeclarativeSpaMode(projectRoot, packageJson) {
  for (const extension of ['js', 'jsx', 'mjs', 'ts', 'tsx']) {
    if (existsSync(join(projectRoot, `react-router.config.${extension}`))) {
      fail('React Router framework configuration is not permitted');
    }
  }
  const mainPath = join(projectRoot, 'src', 'main.jsx');
  const appPath = join(projectRoot, 'src', 'App.jsx');
  if (!existsSync(mainPath) || !existsSync(appPath)) fail('SPA entry points src/main.jsx and src/App.jsx are required');
  const main = readFileSync(mainPath, 'utf8');
  const app = readFileSync(appPath, 'utf8');
  if (!/import\s*\{\s*BrowserRouter\s*\}\s*from\s*['"]react-router-dom['"]/.test(main)) {
    fail('src/main.jsx must prove declarative BrowserRouter library mode');
  }
  const declarativeImport = /import\s*\{[^}]*\bRoutes\b[^}]*\bRoute\b[^}]*\}\s*from\s*['"]react-router-dom['"]/s;
  if (!/<BrowserRouter\b/.test(main) || !declarativeImport.test(app) || !/<Routes\b/.test(app) || !/<Route\b/.test(app)) {
    fail('declarative SPA routing proof is incomplete');
  }
  if (packageJson.scripts?.build !== 'vite build') fail('frontend build must remain client-only Vite');
  for (const sourcePath of productionSources(join(projectRoot, 'src'))) {
    const source = readFileSync(sourcePath, 'utf8');
    for (const [label, pattern] of FORBIDDEN_SOURCE_PATTERNS) {
      if (pattern.test(source)) fail(`${label} is present in production source ${basename(sourcePath)}`);
    }
  }
}

function validateAuditReport(report, record) {
  if (report?.auditReportVersion !== 2) fail('npm audit report version must be 2');
  const vulnerabilityNames = Object.keys(report.vulnerabilities || {}).sort();
  const counts = report.metadata?.vulnerabilities;
  const zeroCounts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
  if (vulnerabilityNames.length === 0) {
    assertExactKeys(counts, Object.keys(zeroCounts), 'audit vulnerability counts');
    for (const [severity, expected] of Object.entries(zeroCounts)) {
      if (counts[severity] !== expected) fail(`audit ${severity} count changed from ${expected}`);
    }
    return;
  }
  assertExactArray(
    vulnerabilityNames,
    [record.package, record.affected_dependent].sort(),
    'audit vulnerability package set',
  );

  const router = report.vulnerabilities[record.package];
  const dependent = report.vulnerabilities[record.affected_dependent];
  if (router.name !== record.package || router.severity !== record.severity || router.isDirect !== false) {
    fail('reviewed transitive vulnerability classification changed');
  }
  if (!Array.isArray(router.via) || router.via.length !== 1 || typeof router.via[0] !== 'object') {
    fail('reviewed advisory must be the only react-router audit cause');
  }
  const advisory = router.via[0];
  const advisoryId = record.advisory_url.split('/').at(-1);
  if (
    advisory.source !== record.advisory_source_id
    || advisory.name !== record.package
    || advisory.dependency !== record.package
    || advisory.url !== record.advisory_url
    || advisory.url.split('/').at(-1) !== advisoryId
    || advisoryId !== record.advisory
    || advisory.title !== 'React Router: RSC Mode CSRF Bypass Allows Action Execution Before 400 Response'
    || advisory.severity !== record.severity
    || advisory.range !== record.advisory_range
  ) {
    fail('npm advisory identity, package, severity, or affected range changed');
  }
  assertExactArray(advisory.cwe, ['CWE-352'], 'advisory CWE');
  if (router.range !== '7.12.0 - 8.2.0') fail('react-router audit node range changed');
  assertExactArray(router.nodes, ['node_modules/react-router'], 'react-router audit nodes');
  assertExactArray(router.effects, [record.affected_dependent], 'react-router audit effects');

  if (
    dependent.name !== record.affected_dependent
    || dependent.severity !== record.severity
    || dependent.isDirect !== true
    || dependent.range !== '>=7.12.0-pre.0'
  ) {
    fail('reviewed direct-dependent vulnerability classification changed');
  }
  assertExactArray(dependent.via, [record.package], 'dependent audit cause');
  assertExactArray(dependent.effects, [], 'dependent audit effects');
  assertExactArray(dependent.nodes, ['node_modules/react-router-dom'], 'dependent audit nodes');

  const expectedCounts = { info: 0, low: 0, moderate: 0, high: 2, critical: 0, total: 2 };
  assertExactKeys(counts, Object.keys(expectedCounts), 'audit vulnerability counts');
  for (const [severity, expected] of Object.entries(expectedCounts)) {
    if (counts[severity] !== expected) fail(`audit ${severity} count changed from ${expected}`);
  }
}

function qualifiedNpmAudit(projectRoot) {
  const npmExecPath = process.env.npm_execpath;
  const executable = npmExecPath ? process.execPath : 'npm';
  const prefix = npmExecPath ? [npmExecPath] : [];
  const version = spawnSync(executable, [...prefix, '--version'], {
    cwd: projectRoot,
    encoding: 'utf8',
  });
  if (version.error || version.status !== 0 || version.stdout.trim() !== '10.8.2') {
    fail(`audit gate requires npm 10.8.2; observed=${version.stdout?.trim() || 'unavailable'}`);
  }
  const audit = spawnSync(executable, [...prefix, 'audit', '--json'], {
    cwd: projectRoot,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (audit.error || ![0, 1].includes(audit.status) || !audit.stdout.trim()) {
    fail(`npm audit did not return a parseable report: ${audit.stderr?.trim() || 'no output'}`);
  }
  try {
    return JSON.parse(audit.stdout);
  } catch (error) {
    fail(`npm audit output is invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function main() {
  const args = parseArguments(process.argv.slice(2));
  const defaultRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const projectRoot = resolve(args.projectRoot || defaultRoot);
  const asOf = args.asOf || new Date().toISOString().slice(0, 10);
  const report = args.auditJson
    ? readJson(resolve(args.auditJson), 'npm audit fixture')
    : qualifiedNpmAudit(projectRoot);
  const vulnerabilityNames = Object.keys(report.vulnerabilities || {});
  if (vulnerabilityNames.length === 0) {
    const packageJson = validateCleanAuditPackages(projectRoot);
    validateDeclarativeSpaMode(projectRoot, packageJson);
    validateAuditReport(report);
    console.log('PASS npm-audit vulnerabilities=0 disposition=NO_VULNERABILITIES');
  } else {
    const record = validateExceptionRecord(projectRoot, asOf);
    const { packageJson } = validatePinnedPackages(projectRoot, record);
    validateDeclarativeSpaMode(projectRoot, packageJson);
    validateAuditReport(report, record);
    console.log(
      `PASS npm-audit advisory=${record.advisory} package=${record.package}@${record.installed_version} `
      + `dependent=${record.affected_dependent}@${record.affected_dependent_version} `
      + `disposition=${record.disposition} mode=declarative_browser_spa expires=${record.expires_on}`,
    );
  }
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`FAIL npm-audit: ${message}`);
  process.exitCode = 1;
}
