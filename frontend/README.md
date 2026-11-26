# Develop the Vesta web console

For installation, download the prebuilt kit from [GitHub Releases](https://github.com/Insitu-IT/vesta/releases/latest). The commands below are for contributors changing or testing the console. It uses Tabler, Bootstrap and Vite. Run these commands from
`frontend/` with Node.js 24 and its bundled npm.

```sh
npm ci
node scripts/extract-api-calls.cjs
node --experimental-vm-modules --test tests/*.test.mjs
npm run build
```

`npm ci` installs dependencies from the committed lockfile. The production
build writes to `dist/` and checks the frontend bundle for that edition.

## Local development

Start the Vesta API on port 8000, then run `npm run dev` and open
`http://localhost:3000`. Vite proxies requests under `/api` to the local API.
Set `API_URL` when starting Vite to use a different backend.

```sh
API_URL=http://127.0.0.1:8001 npm run dev
```

The application entry point is `src/main.js`. Shared pages live under
`src/pages/`, and styling lives under `src/styles/`.

## Editions

The default build uses `src/editions/community.js` and runs without a
`commercial/` directory. The commercial build requires the separate
`commercial/frontend/` source tree. Keep shared pages and services independent
of that tree so a Community checkout can build and run on its own.
