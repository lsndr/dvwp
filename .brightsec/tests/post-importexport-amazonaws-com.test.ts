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

test('POST /importexport.amazonaws.com', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'id_enumeration', 'secret_tokens', 'sqli'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.QUERY],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/importexport.amazonaws.com?Action=DescribeJob&JobId=EXAMPLE123`,
      body: 'Action=DescribeJob&JobId=EXAMPLE123',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});