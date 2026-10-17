# Datum Connect for Android

Opens services shared with `datumctl connect local` on this phone. Scan the QR
code that `local` prints, tap **Connect**, then **Open**. No Datum account or
login is needed.

The app holds several connections at once, each on its own local port. Each
takes the name set with `datumctl connect local --name` (default
`HOSTNAME:PORT`), and you can rename it in the app.

The app is a thin Kotlin UI over the Rust `connect-share` crate, the same code
`datumctl connect dial TICKET` uses. See
[project-less local tunnels](../../docs/design/project-less-local-tunnels.md).

## Build

Use the Android dev shell from the repository root. It provides the Android
SDK and NDK, JDK 17, Gradle, cargo-ndk, and the Rust Android targets.

```sh
nix develop .#android
cd connect-mobile/android

# All ABIs, optimized Rust library
gradle assembleDebug

# Faster: one ABI, debug Rust library (for the x86_64 emulator)
gradle assembleDebug -PrustProfile=debug -PrustAbis=x86_64
```

The build runs two Rust steps before Gradle compiles the app:

| Task | What it does |
|---|---|
| `cargoNdk` | Builds `libconnect_share_ffi.so` for each ABI into `app/src/main/jniLibs/` (ignored by git). |
| `uniffiBindings` | Builds the crate for the host and generates Kotlin bindings into `app/build/generated/uniffi/`. |

The APK is `app/build/outputs/apk/debug/app-debug.apk`.

## Try it

On a computer:

```sh
python3 -m http.server 9999 &
datumctl connect local --port 9999
```

On the phone, scan the QR code and tap **Connect**. The app keeps a foreground
notification while the port is open. Tap **Stop** there or in the app to close
it.

In the emulator, paste the ticket instead of scanning: run
`adb shell input text 'DCSHARE2…'` with the field focused, or use **Paste**
after copying the ticket into the emulator's clipboard.

## Update the app without a public URL

Once the app is installed, use it to download newer builds. The script builds
an APK, serves it from a loopback web server, and shares that port with
`datumctl connect local`:

```sh
nix develop .#android
cd connect-mobile/android
scripts/share-apk.sh              # build arm64-v8a, then share
scripts/share-apk.sh --no-build   # share the last debug APK
```

In the app, scan the QR code, tap **Connect**, then **Open** on the
"Datum Connect APK" card, and tap **Download APK**. Android installs it over the current app only when both
are signed with the same key. Debug builds use each machine's
`~/.android/debug.keystore`, so build updates on the machine that built the
installed app. The share allows one device and stops with Ctrl+C.

Set `CONNECT` to run a different plugin binary, for example
`CONNECT=../../connect-plugin/datumctl-connect scripts/share-apk.sh`.

## Layout

| Path | Purpose |
|---|---|
| `app/src/main/java/.../MainActivity.kt` | Connection cards, add form, QR scan, rename |
| `app/src/main/java/.../Connections.kt` | Connection list, unique names, port choice |
| `app/src/main/java/.../DialService.kt` | Foreground service that runs one dial per connection |
| `app/src/main/java/.../DeviceKey.kt` | This phone's iroh key, in app-private no-backup storage |
| `../../connect-lib/share-ffi` | UniFFI surface: `parseTicket`, `generateDeviceKey`, `DialSession` |

## Release signing

Not configured yet. Release builds will be signed in CI from secrets. Never
commit a keystore or its passwords.
