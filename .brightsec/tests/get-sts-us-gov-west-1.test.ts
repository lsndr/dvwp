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

test('GET /sts-us-gov-west-1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['insecure_tls_configuration', 'open_cloud_storage', 'amazon_s3_takeover', 'csrf', 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.HEADER],
      starMetadata: {
        code_source: "lsndr/dvwp:master",
        databases: ["MySQL"],
        user_roles: { roles: [] }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/sts-us-gov-west-1`,
      headers: {
        'Host': 'sts.us-gov-west-1.amazonaws.com',
        'x-amz-date': '20231101T000000Z',
        'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231101/us-gov-west-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=EXAMPLESIGNATURE'
      }
    });
});