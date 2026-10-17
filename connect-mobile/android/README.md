# Datum Connect for Android

Opens a service shared with `datumctl connect local` on this phone. Scan the QR
code that `local` prints, tap **Connect**, then **Open in browser**. No Datum
account or login is needed.

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

## Layout

| Path | Purpose |
|---|---|
| `app/src/main/java/.../MainActivity.kt` | Ticket entry, QR scan, status, open in browser |
| `app/src/main/java/.../DialService.kt` | Foreground service that owns the running dial |
| `app/src/main/java/.../DeviceKey.kt` | This phone's iroh key, in app-private no-backup storage |
| `../../connect-lib/share-ffi` | UniFFI surface: `parseTicket`, `generateDeviceKey`, `DialSession` |

## Release signing

Not configured yet. Release builds will be signed in CI from secrets. Never
commit a keystore or its passwords.
