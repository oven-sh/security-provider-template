import {expect, test} from 'bun:test';
import {scanner} from './src/index.ts';

/////////////////////////////////////////////////////////////////////////////////////
//  This test file is mostly just here to get you up and running quickly. It's
//  likely you'd want to improve or remove this, and add more coverage for your
//  own code.
/////////////////////////////////////////////////////////////////////////////////////

test('Scanner should warn about known malicious packages', async () => {
	const advisories = await scanner.scan({
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
	const advisories = await scanner.scan({packages: []});
	expect(advisories.length).toBe(0);
});

test('Safe packages should return no advisories', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'lodash',
				version: '4.17.21',
				requestedRange: '^4.17.0',
				tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
			},
		],
	});
	expect(advisories.length).toBe(0);
});

test('Should handle multiple packages with mixed security status', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: 'event-stream',
				version: '3.3.6', // malicious
				requestedRange: '^3.3.0',
				tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz',
			},
			{
				name: 'lodash',
				version: '4.17.21', // safe
				requestedRange: '^4.17.0',
				tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
			},
		],
	});

	expect(advisories.length).toBe(1);
	expect(advisories[0]?.package).toBe('event-stream');
});

test('Should differentiate between versions of the same package', async () => {
	const maliciousVersion = await scanner.scan({
		packages: [
			{
				name: 'event-stream',
				version: '3.3.6', // malicious version
				requestedRange: '3.3.6',
				tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz',
			},
		],
	});

	const safeVersion = await scanner.scan({
		packages: [
			{
				name: 'event-stream',
				version: '4.0.0', // safe version
				requestedRange: '4.0.0',
				tarball: 'https://registry.npmjs.org/event-stream/-/event-stream-4.0.0.tgz',
			},
		],
	});

	expect(maliciousVersion.length).toBeGreaterThan(0);
	expect(safeVersion.length).toBe(0);
});

test('Should handle scoped packages correctly', async () => {
	const advisories = await scanner.scan({
		packages: [
			{
				name: '@types/node',
				version: '20.0.0',
				requestedRange: '^20.0.0',
				tarball: 'https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz',
			},
		],
	});

	expect(advisories.length).toBe(0);
});
