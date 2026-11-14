import { readFileSync } from 'node:fs';

const ADVISORY_DATA = JSON.parse(readFileSync(new URL('./advisories.json', import.meta.url), 'utf8'));
const FIXED_RELEASES = ADVISORY_DATA.fixedReleases;
const CVES = ADVISORY_DATA.cves;

function extractBodyPhpVersion(body) {
  if (!body) return null;
  // Require phpinfo() markup structure so ordinary prose mentioning "PHP Version X.Y.Z" does not false-positive.
  const structuredMatch = body.match(
    /<h[1-6][^>]*>\s*PHP\s+Version\s+(\d+\.\d+\.\d+)\b([-+][a-z0-9.~+_-]+)?|<td[^>]*>\s*PHP\s+Version\s*<\/td>\s*<td[^>]*>\s*(\d+\.\d+\.\d+)\b([-+][a-z0-9.~+_-]+)?/i
  );
  if (structuredMatch) {
    return {
      version: structuredMatch[1] || structuredMatch[3],
      vendorSuffix: structuredMatch[2] || structuredMatch[4] || null
    };
  }
  const looksLikePhpInfo = /phpinfo\s*\(\)|module_Core|<title>\s*phpinfo\s*\(\)\s*<\/title>/i.test(body);
  if (!looksLikePhpInfo) return null;
  const fallbackMatch = body.match(/PHP\s+Version(?:(?:\s|<[^>]*>)){0,24}(\d+\.\d+\.\d+)\b([-+][a-z0-9.~+_-]+)?/i);
  if (!fallbackMatch) return null;
  return { version: fallbackMatch[1], vendorSuffix: fallbackMatch[2] || null };
}

function classifyPhp(headers, body = '') {
  const exposed = `${headers['x-powered-by'] || ''} ${headers.server || ''}`;
  const headerMatch = exposed.match(/\bPHP(?:\s*\/\s*|\s+)(\d+\.\d+\.\d+)\b([-+][a-z0-9.~+_-]+)?/i);
  const infoMatch = headerMatch ? null : extractBodyPhpVersion(body);
  const zendMatch = (headerMatch || infoMatch) ? null : body.match(/Zend Engine\s+v?4\.(\d+)\.(\d+)\b/i);

  const version = headerMatch?.[1] || infoMatch?.version || (zendMatch ? `8.${zendMatch[1]}.${zendMatch[2]}` : null);
  if (!version) return { version: null, versionSource: null, assessment: 'Version not disclosed' };

  const versionSource = headerMatch ? 'HTTP header' : infoMatch ? 'PHP response' : 'Zend Engine';
  const vendorSuffix = headerMatch?.[2] || infoMatch?.vendorSuffix || null;
  const parts = version.split('.').map(Number);
  const branch = `${parts[0]}.${parts[1]}`;

  if (FIXED_RELEASES[branch]) {
    const [fixedMajor, fixedMinor, fixedPatch] = FIXED_RELEASES[branch].split('.').map(Number);
    const isOlder = parts[0] < fixedMajor ||
      (parts[0] === fixedMajor && parts[1] < fixedMinor) ||
      (parts[0] === fixedMajor && parts[1] === fixedMinor && parts[2] < fixedPatch);
    return {
      version,
      versionSource,
      ...(vendorSuffix ? { vendorSuffix } : {}),
      affectedCandidate: isOlder,
      assessment: isOlder
        ? (vendorSuffix ? 'Below fixed release (candidate; vendor suffix present)' : 'Below fixed release (candidate)')
        : 'At/above fixed release'
    };
  }
  if (parts[0] < 8 || (parts[0] === 8 && parts[1] <= 1)) {
    return {
      version,
      versionSource,
      ...(vendorSuffix ? { vendorSuffix } : {}),
      affectedCandidate: true,
      assessment: 'Legacy branch; vendor backport unknown'
    };
  }
  return {
    version,
    versionSource,
    ...(vendorSuffix ? { vendorSuffix } : {}),
    affectedCandidate: false,
    assessment: 'Verify vendor package status'
  };
}

function inspectPhpInfoFix(body, truncated = false) {
  const looksLikePhpInfo = /phpinfo\s*\(\)|PHP Version|module_Core/i.test(body);
  if (!looksLikePhpInfo) return null;
  if (/memory_hard_limit_percent/i.test(body)) return 'present';
  const hasCoreTable = /module_Core|>\s*Core\s*</i.test(body);
  return hasCoreTable && !truncated ? 'absent' : null;
}

function hasPhpSignal(headers, body, detected) {
  return Boolean(
    detected?.version ||
    /PHPSESSID/i.test(headers['set-cookie'] || '') ||
    /\bPHP\s+(?:Fatal error|Warning|Notice|Deprecated|Parse error):/i.test(body)
  );
}

export { CVES, FIXED_RELEASES, classifyPhp, hasPhpSignal, inspectPhpInfoFix };
