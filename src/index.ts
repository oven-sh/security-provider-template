// This is just an example interface of mock data. You can change this to the
// type of your actual threat feed (or ideally use a good schema validation
// library to infer your types from).
interface ThreatFeedItem {
	package: string;
	range: string;
	url: string | null;
	description: string | null;
	categories: Array<'protestware' | 'adware' | 'backdoor' | 'malware' | 'botnet'>;
}

async function fetchThreatFeed(packages: Bun.Security.Package[]): Promise<ThreatFeedItem[]> {
	// In a real provider you would probably replace this mock data with a
	// fetch() to your threat feed, validating it with Zod or a similar library.

	const myPretendThreatFeed: ThreatFeedItem[] = [
		{
			package: 'event-stream',
			range: '>=3.3.6 <4.0.0', // Matches 3.3.6 and above but less than 4.0.0
			url: 'https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident',
			description: 'event-stream is a malicious package',
			categories: ['malware'],
		},
		// ...
	];

	return myPretendThreatFeed.filter(item => {
		return packages.some(
			p => p.name === item.package && Bun.semver.satisfies(p.version, item.range),
		);
	});
}

export const scanner: Bun.Security.Scanner = {
	version: '1', // This is the version of Bun security scanner implementation. You should keep this set as '1'
	async scan({packages}) {
		const feed = await fetchThreatFeed(packages);

		// Iterate over reported threats and return an array of advisories. This
		// could be longer, shorter or equal length of the input packages array.
		// Whatever you return will be shown to the user.

		const results: Bun.Security.Advisory[] = [];

		for (const item of feed) {
			// Advisory levels control installation behavior:
			// - All advisories are always shown to the user regardless of level
			// - Fatal: Installation stops immediately (e.g., backdoors, botnets)
			// - Warning: User prompted in TTY, auto-cancelled in non-TTY (e.g., protestware, adware)

			const isFatal =
				item.categories.includes('malware') ||
				item.categories.includes('backdoor') ||
				item.categories.includes('botnet');

			const isWarning =
				item.categories.includes('protestware') || item.categories.includes('adware');

			if (!isFatal && !isWarning) continue;

			// Besides the .level property, the other properties are just here
			// for display to the user.
			results.push({
				level: isFatal ? 'fatal' : 'warn',
				package: item.package,
				url: item.url,
				description: item.description,
			});
		}

		// Return an empty array if there are no advisories!
		return results;
	},
};
