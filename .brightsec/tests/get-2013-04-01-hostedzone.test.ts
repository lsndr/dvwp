import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /2013-04-01/hostedzone', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['business_constraint_bypass', 'improper_asset_management', 'insecure_tls_configuration', 'id_enumeration', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'lsndr/dvwp:master',
        databases: ['MySQL'],
        user_roles: { roles: [] }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/2013-04-01/hostedzone?maxitems=100&name=example.com`,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231101/us-east-1/route53/aws4_request, SignedHeaders=host;x-amz-date, Signature=EXAMPLESIGNATURE'
      }
    });
});