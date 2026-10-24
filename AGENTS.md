Read @README.md

# Building and testing

Run every command from the repository root unless a step says otherwise.

## Dev shells

| Shell | Use it for | Provides |
|---|---|---|
| `nix develop` | Rust, Go, nix package, Linux and macOS archives | Rust from `connect-lib/rust-toolchain.toml` (on macOS with `aarch64-apple-darwin` and `x86_64-apple-darwin`), Go, task, pkg-config, OpenSSL |
| `nix develop .#android` | The Android app | Rust with the Android targets, cargo-ndk, Android SDK and NDK, JDK 17, Gradle |

Run one command in a shell with `nix develop -c <command>`. If Go reports `error obtaining VCS status`, for example in a nested checkout, set `GOFLAGS=-buildvcs=false`.

## Rust (`connect-lib/`)

```sh
cd connect-lib
cargo build -p datum-connect-daemon        # target/debug/datum-connectd
cargo build --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The share and transport crates have their own suites: `cargo test -p connect-share -p connect-transport`.

## Go plugin (`connect-plugin/`)

```sh
cd connect-plugin
go build -o datumctl-connect .
go vet ./...
go test -timeout 5m ./...
```

The plugin looks for `datum-connectd` next to itself, then in `PATH`. For local testing, put a symlink to `connect-lib/target/debug/datum-connectd` next to the plugin binary. A broken symlink there is reported as an error, not skipped.

## Taskfile

| Task | What it does |
|---|---|
| `task build` | Debug plugin and daemon |
| `task build:release` | Plugin and release daemon (LTO, stripped) |
| `task test` | Go and Rust unit tests |
| `task test:e2e:local` | `datumctl connect local` and ticket dial against a real `datum-connectd`, relays disabled |
| `task test:e2e` | CLI, daemon, and iroh end to end with a simulated control plane |
| `task install` | Copy both binaries to `~/.datumctl/plugins/` |

## Nix package

```sh
nix build            # datum-connectd, runs the workspace tests in the sandbox
nix flake check
```

Git dependencies need a pinned hash in `cargoLock.outputHashes` in `flake.nix`; today that is only `h3`. When its rev in `Cargo.lock` changes, set the hash to `pkgs.lib.fakeHash`, run `nix build`, and copy the `got:` hash from the error. Registry crates need no hash.

## Android app (`connect-mobile/android/`)

Inside `nix develop .#android`, from `connect-mobile/android`:

```sh
gradle assembleDebug                                         # all ABIs
gradle assembleDebug -PrustProfile=debug -PrustAbis=x86_64   # fast, emulator only
gradle testDebugUnitTest -PrustProfile=debug -PrustAbis=x86_64
```

Debug builds install as a separate app, `net.datum.connect.share.debug` ("Datum Connect (dev)"), beside the release app.

Release builds need the release keystore, which lives outside the repository in `~/.config/datum-connect/android-release/`. Never commit it or its passwords. Losing it means installed copies can no longer be updated.

```sh
export DATUM_CONNECT_SIGNING=~/.config/datum-connect/android-release/signing.properties
gradle clean assembleRelease
```

Check the result with `aapt2 dump badging` (versionCode is the commit count, versionName is `0.1.0+$(git describe --tags --always --dirty)`) and `apksigner verify --print-certs`. The release certificate SHA-256 is `2c3ad24e6b2900002bbaf2ca78208bc2337ab1cb5600481f085e3ef8d0336724`.

`scripts/share-apk.sh` sends a build to a phone that already has the app, over a project-less share.

## Linux archives

```sh
nix develop -c scripts/build-linux-share.sh
```

Builds `dist/share/datum-connect-linux-{x86_64,arm64}.tar.gz` in an Ubuntu 22.04 container, so it needs Docker. Each archive holds `datumctl-connect`, `datum-connectd`, `LICENSE`, and `VERSION`.

## macOS archives

On a Mac with the Xcode command line tools:

```sh
nix develop -c scripts/build-macos-share.sh
```

Builds `dist/share/datum-connect-macos-{arm64,x86_64}.tar.gz`. Outside the dev shell the script uses rustup to add any Apple target the active Rust lacks, and needs Go on `PATH`. The binaries are ad-hoc signed only, not notarized.

## Diagnostics image for Datum Compute

`connect-lib/share-diag/Dockerfile.datum` builds `datum-connect-diag` as a static-PIE musl binary in an empty image, which the unikernel runtime requires. Build it from `connect-lib` so the workspace is in context; the Dockerfile header has the command.

## Publishing downloads

Downloads go to the public `datum-download` S3 bucket and are listed at <https://datum-download.s3.us-east-2.amazonaws.com/connect/index.html>. Publish only clean builds: commit and push first, and check that `VERSION` or versionName has no `-dirty` suffix.

```sh
aws sso login --profile datum-sandbox-admin   # over SSH add --use-device-code --no-browser
AWS_PROFILE=datum-sandbox-admin nix develop .#android -c connect-mobile/android/scripts/publish-apk.sh
AWS_PROFILE=datum-sandbox-admin nix develop -c scripts/downloads/publish-cli.sh linux
AWS_PROFILE=datum-sandbox-admin scripts/downloads/publish-cli.sh macos     # on the Mac
```

Each publish uploads immutable, dated files, replaces that platform's `latest.json`, and re-renders the page with `scripts/downloads/page.py`, leaving the other platforms as they are. Changing the ticket format or a command people copy means republishing every platform, since older builds reject newer tickets.
