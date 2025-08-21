<img src="https://bun.com/logo.png" height="36" />

# Bun Security Scanner Template

A template for creating a security scanner for Bun's package installation
process. Security scanners scan packages against your threat intelligence feeds
and control whether installations proceed based on detected threats.

📚 [**Full documentation**](https://bun.com/docs/install/security-scanner-api)

## How It Works

When packages are installed via Bun, your security scanner:

1. **Receives** package information (name, version)
2. **Queries** your threat intelligence API
3. **Validates** the response data
4. **Categorizes** threats by severity
5. **Returns** advisories to control installation (empty array if safe)

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

When fetching threat feeds over the network, use schema validation  
(e.g., Zod) to ensure data integrity. Invalid responses should fail immediately
rather than silently returning empty advisories.

```typescript
import {z} from 'zod';

const ThreatFeedItemSchema = z.object({
	package: z.string(),
	version: z.string(),
	url: z.string().nullable(),
	description: z.string().nullable(),
	categories: z.array(z.enum(['backdoor', 'botnet' /* ... */])),
});
```

### Useful Bun APIs

Bun provides several built-in APIs that are particularly useful for security scanner:

- [**Security scanner API Reference**](https://bun.com/docs/install/security-scanner-api): Complete API documentation for security scanners
- [**`Bun.semver.satisfies()`**](https://bun.com/docs/api/semver): Essential for checking if package versions match vulnerability ranges. No external dependencies needed.

  ```typescript
  if (Bun.semver.satisfies(version, '>=1.0.0 <1.2.5')) {
  	// Version is vulnerable
  }
  ```

- [**`Bun.hash`**](https://bun.com/docs/api/hashing#bun-hash): Fast hashing for package integrity checks
- [**`Bun.file`**](https://bun.com/docs/api/file-io): Efficient file I/O, could be used for reading local threat databases

## Testing

This template includes tests for a known malicious package version.
Customize the test file as needed.

```bash
bun test
```

## Publishing Your Provider

Publish your security scanner to npm:

```bash
bun publish
```

Users can now install your provider and add it to their `bunfig.toml` configuration.

To test locally before publishing, use [`bun link`](https://bun.sh/docs/cli/link):

```bash
# In your provider directory
bun link

# In your test project
bun link @acme/bun # this is the name in package.json of your provider
```

## Contributing

This is a template repository. Fork it and customize for your organization's
security requirements.

## Support

For docs and questions, see the [Bun documentation](https://bun.com/docs/install/security-scanner-api) or [Join our Discord](https://bun.com/discord).

For template issues, please open an issue in this repository.
