# Bun Security Provider Template

A template for creating custom security providers for Bun's package installation
process. Security providers allow you to scan packages against your own threat
intelligence feeds and control the installation flow based on security
advisories.

## How It Works

When packages are installed via Bun, your security provider should:

1. **Receive** package information (name, version)
2. **Querie** your threat intelligence API
3. **Validate** the response data
4. **Categorize** threats based on severity
5. **Return** an array of advisories that control installation behavior. Return
   an empty array if there are no advisories.

### Advisory Levels

- **Fatal** (`level: 'fatal'`): Installation stops immediately
  - Examples: backdoors, botnets, critical vulnerabilities
- **Warning** (`level: 'warn'`): User prompted for confirmation
  - In TTY: User can choose to continue or cancel
  - Non-TTY: Installation automatically cancelled
  - Examples: protestware, adware, deprecated packages

All advisories are always displayed to the user regardless of level.

### Validation

The template implements simple validation for the sake of keeping the template
simple. Consider using a schema validation library like Zod for production:

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

## Testing

This template comes with a test file already setup. It tests for known malicious
packages that exist on npm

```bash
bun test
```

## Contributing

This is a template repository. Fork it and customize for your organization's
security requirements.

## Support

For Bun-specific questions, see the [Bun documentation](https://bun.com/docs).

For template issues, please open an issue in this repository.
