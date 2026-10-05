# Contributing to firc

## Commits

Conventional Commits: `type(scope): subject`. The subject is at most 70
characters of plain English. Add a body only if it is needed, and then as
one line `*note` of at most five words.

```
fix(dns): clamp TTL on collapsed answers
feat(api): add group list sync events

*keeps old clients working
```

## Before a pull request

Run the gates (see [BUILDING.md](BUILDING.md)) and make sure each one exits 0:

- from `src/backend-c/`: `make test`, `make sanitize`, `make static_analysis`
  and the differential suite;
- if you touched `src/frontend/`: `npm run format:check`, `npm run check`,
  `npm run test:unit` and `npm run test:e2e`.

A change in behaviour needs a test that fails without it. A new HTTP route
needs its entry in `docs/swagger.yaml`.

## License

firc is GPL-3.0-or-later; your contribution is licensed under the same terms.
