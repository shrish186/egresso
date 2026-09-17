# Contributing to agentwall

Thanks for helping make AI agents safer to run.

## The most valuable contribution: break it

agentwall is a security tool. If you can sneak a secret out or run a destructive
command past it, that's a bug we want. Open an issue titled `bypass:` with the exact
command. We'll reproduce it, add it to `test/bypass.test.ts`, and fix it.

## Dev setup

```bash
npm install
npm run build
npm test
```

## Adding a detection rule

- Secret sources / network sinks: `src/enforce/dataflow.ts`
- Secret formats: `src/detect/secrets.ts`
- Destructive commands: `src/enforce/destructive.ts`

Every new rule needs a test in `test/` — one case that should trigger it, and one
similar-but-legitimate case that must NOT (false positives make people uninstall).

## Pull requests

Keep them focused. Run `npm test` before pushing. New behavior needs tests.
