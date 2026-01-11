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

test('GET /s3-cn-north-1.amazonaws.com.cn?Action=ListBuckets&Version=2006-03-01', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['amazon_s3_takeover', 'open_cloud_storage', 'insecure_tls_configuration', 'improper_asset_management'],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY],
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
      url: `${baseUrl}/s3-cn-north-1.amazonaws.com.cn?Action=ListBuckets&Version=2006-03-01`,
      headers: {
        Authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=EXAMPLESIGNATURE',
        'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
        'x-amz-date': '20231101T000000Z'
      }
    });
});