# Contributing

## Language and examples

Write all project documentation, source comments, user-facing messages, CLI/MCP descriptions, skills, examples, test names, release notes and commit messages in English. README.md is the English entry point; README.zh-TW.md is the Traditional Chinese translation. These README editions are the only documentation language exception. Keep their instructions and supported behavior aligned.

Non-English input is supported. Unicode regression fixtures and multilingual lookup keys may use explicit Unicode escapes, with English explanations. Do not translate arbitrary user data or weaken Unicode tests to satisfy the writing policy.

Keep removed application-specific examples out of distributed files and documentation. Prefer small source-owned fixtures with explicit inputs, outputs, provenance and limitations. Do not commit local analysis workspaces, binaries, credentials, function catalogs or shared agent memory.

## Checks

Use a supported Node version and run:

```sh
npm ci
npm run check
```

The release check builds TypeScript, runs tests, exercises the archive demo and public packages, verifies a clean tarball installation, and checks repository language/content hygiene. Native/mobile integrations need their documented engines and references; passing core checks does not imply those integrations were rerun.

REA MCP and RECarve MCP remain independent. Explain what changed, which checks actually ran and what remains unverified. A submitted implementation is not accepted or integrated solely because an agent reports success.
