import { expect, test } from 'bun:test';
import { provider } from './src/index.ts';

/////////////////////////////////////////////////////////////////////////////////////
//  This test file is mostly just here to get you up and running quickly. It's
//  likely you'd want to improve or remove this, and add more coverage for your
//  own code.
/////////////////////////////////////////////////////////////////////////////////////

test('Provider should warn about known malicious packages', async () => {
	const advisories = await provider.scan({
		packages: [
			{
				name: 'event-stream',
				version: '3.3.6', // This was a known incident in 2018 - https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
				requestedRange: '^3.3.0',
				tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz',
			},
		],
	});

	expect(advisories.length).toBeGreaterThan(0);
	const advisory = advisories[0]!;
	expect(advisory).toBeDefined();

	expect(advisory).toMatchObject({
		level: 'fatal',
		package: 'event-stream',
		url: expect.any(String),
		description: expect.any(String),
	});
});

test('There should be no advisories if no packages are being installed', async () => {
	const advisories = await provider.scan({ packages: [] });
	expect(advisories.length).toBe(0);
});
