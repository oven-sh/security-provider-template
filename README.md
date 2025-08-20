<img src="https://bun.com/logo.png" height="36" />

# Bun Security Provider Template

> [!WARNING]
> This feature is currently unfinished but will be shipping soon. Track progress at https://github.com/oven-sh/bun/pull/21183

A template for creating custom security providers for Bun's package installation
process. Security providers allow you to scan packages against your own threat
intelligence feeds and control the installation flow based on security
advisories.

## How It Works

When packages are installed via Bun, your security provider should:

1. **Receive** package information (name, version)
2. **Query** your threat intelligence API
3. **Validate** the response data
4. **Categorize** threats based on severity
5. **Return** an array of advisories that control installation behavior. Return
   an empty array if there are no advisories.

### Advisory Levels

- **Fatal** (`level: 'fatal'`): Installation stops immediately
  - Examples: malware, token stealers, backdoors, critical vulnerabilities
- **Warning** (`level: 'warn'`): User prompted for confirmation
  - In TTY: User can choose to continue or cancel
  - Non-TTY: Installation automatically cancelled
  - Examples: protestware, adware, deprecated packages

All advisories are always displayed to the user regardless of level.

### Error Handling

If your `scan` function throws an error, it will be gracefully handled by Bun, but the installation process **will be cancelled** as a defensive precaution.

### Validation

If you fetch a threat feed over the network, perhaps from your own API, consider
using a schema validation library like Zod for production. This code needs to be
defensive in all cases, so we should fail if we receive an invalid thread feed,
rather than continuining and potentially returning an empty array of advisories.
It's better to fail fast here.

```typescript
import { z } from 'zod';

const ThreatFeedItemSchema = z.object({
	package: z.string(),
	version: z.string(),
	url: z.string().nullable(),
	description: z.string().nullable(),
	categories: z.array(z.enum(['backdoor', 'botnet' /* ... */])),
});
```

### Useful Bun APIs

Bun provides several built-in APIs that are particularly useful for security providers:

- **`Bun.semver.satisfies()`**: Essential for checking if package versions match vulnerability ranges. No external dependencies needed.

  ```typescript
  if (Bun.semver.satisfies(version, '>=1.0.0 <1.2.5')) {
  	// Version is vulnerable
  }
  ```

- [**`Bun.hash`**](https://bun.com/docs/api/hashing#bun-hash): Fast hashing for package integrity checks
- [**`Bun.file`**](https://bun.com/docs/api/file-io): Efficient file I/O, could be used for reading local threat databases

## Testing

This template comes with a test file already setup. It tests for a known
malicious package version. You can remove or edit this test file as you see fit.

```bash
bun test
```

## Publishing Your Provider

Publishing your security provider is straightforward - simply publish it to npm:

```bash
bun publish
```

That's it! Once published, users can configure Bun to use your security provider
by installing it in the project and adding it to their `bunfig.toml`
configuration file.

## Contributing

This is a template repository. Fork it and customize for your organization's
security requirements.

## Support

For docs and questions, see the [Bun documentation](https://bun.com/docs/install/security) or [Join our Discord](https://bun.com/discord).

For template issues, please open an issue in this repository.
