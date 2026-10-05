# firc WebUI

The web interface `fircd` serves, in Svelte 5 and TypeScript.

## Build

```sh
npm ci
npm run build           # into dist/
```

## Develop

Run the mock API and the dev server in two terminals (the mock needs Deno):

```sh
npm run dev:backend     # mock API from dev/backend-mock.ts
npm run dev:frontend    # Vite dev server
```

## Check

```sh
npm run check           # svelte-check + tsc
npm run format:check    # Prettier (npm run format to fix)
npm run check:i18n      # translation keys
npm run test:unit       # Deno unit tests
npm run test:e2e        # Playwright end-to-end tests
```
