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

test('GET /bucket-name/object-key', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['amazon_s3_takeover', 'open_cloud_storage', 'csrf'],
      attackParamLocations: [
        AttackParamLocation.HEADER,
        AttackParamLocation.QUERY
      ],
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
      url: `${baseUrl}/bucket-name/object-key?response-cache-control=no-cache&response-content-disposition=attachment%3B%20filename%3D%22filename.jpg%22&response-content-encoding=gzip&response-content-language=en-US&response-content-type=application/json&response-expires=Wed%2C%2021%20Oct%202025%2007%3A28%3A00%20GMT&versionId=3%2FL4kqtJlcpXroDTDmJ%2BrmSpXd3dIbrHY`,
      headers: {
        'IfMatch': '"etagvalue"',
        'IfModifiedSince': 'Wed, 21 Oct 2015 07:28:00 GMT',
        'IfNoneMatch': '"etagvalue"',
        'IfUnmodifiedSince': 'Wed, 21 Oct 2015 07:28:00 GMT',
        'Range': 'bytes=0-9',
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'base64-encoded-key',
        'x-amz-server-side-encryption-customer-key-MD5': 'base64-encoded-md5',
        'x-amz-request-payer': 'requester'
      }
    });
});