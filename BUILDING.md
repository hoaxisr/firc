# Building firc

firc ships as an `.ipk` for Keenetic routers running Entware. The supported
targets are the files in `config/entware/`: `aarch64-3.10_kn`,
`mipsel-3.4_kn` and `mips-3.4_kn` (big-endian, experimental).

## Configure

```sh
cp .config.example .config
```

`.config` sets `PLATFORM` (always `entware`), `TARGET` (one of the names in
`config/entware/`), and optionally `CROSS_COMPILE` (a toolchain prefix such
as `mipsel-linux-gnu-`) and `SYSROOT`. With both left empty the backend is
built for the host, which is what the tests use. Entware is glibc: build
against the Entware SDK's toolchain and sysroot, never against musl or the
host's glibc.

## Build and package

From the repository root:

```sh
make all              # download dependencies, build, package
make build            # backend and frontend only
make build_backend    # the C daemon only
make build_frontend   # the Svelte WebUI only
make package          # the .ipk
make clean            # remove all build artifacts
make clear            # remove the build dir for the current PLATFORM/TARGET and the frontend dist
```

Build output lands in `.build/<PLATFORM>_<TARGET>/`; the packages in `.build/`.

## Backend

The daemon is C11 in `src/backend-c/`. Host libraries: libyaml, PCRE2,
libmnl, cJSON and libcurl (development headers). From `src/backend-c/`:

```sh
make                          # build/host/fircd and the test tools
make test                     # unit tests, one binary per tests/unit/test_*.c
make sanitize                 # unit tests under ASan + UBSan
make static_analysis          # clang-tidy + cppcheck
make fuzz FUZZ_RUNS=200000    # libFuzzer targets (needs clang)
```

One unit test binary, or one case in it:

```sh
make build/host/tests/test_match && build/host/tests/test_match
build/host/tests/test_match -t some_test_name
```

The differential suite compares the daemon against snapshots in
`tests/differential/golden/`. Part of it needs real iptables and `/run`;
a user namespace gives it both without root:

```sh
T=$(mktemp -d); mkdir -p "$T/up" "$T/work"
unshare -Urmn sh -c "mount -t tmpfs tmpfs /run; ip link set lo up; \
  mount -t overlay overlay -o lowerdir=/etc,upperdir=$T/up,workdir=$T/work /etc; \
  cd $PWD && sh tests/differential/run_diff.sh"
rm -rf "$T"
```

## Frontend

The WebUI is Svelte 5 + TypeScript in `src/frontend/`. It needs Node.js
and npm; the mock backend and the unit tests also need Deno.

```sh
cd src/frontend
npm ci
npm run dev:backend     # mock API (dev/backend-mock.ts)
npm run dev:frontend    # Vite dev server, in a second terminal
npm run build           # production build into dist/
npm run check           # svelte-check + tsc
npm run format          # Prettier
npm run format:check    # Prettier, check only
npm run test:unit       # Deno unit tests
npm run test:e2e        # Playwright end-to-end tests
```
