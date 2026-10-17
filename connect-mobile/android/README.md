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

Release builds are signed when `DATUM_CONNECT_SIGNING` names a properties file
outside the repository:

```properties
storeFile=/home/you/.config/datum-connect/android-release/release.jks
storePassword=...
keyAlias=datum-connect
keyPassword=...
```

Without it, release builds are unsigned. The current key is an EC P-256 key
with certificate SHA-256
`2c3ad24e6b2900002bbaf2ca78208bc2337ab1cb5600481f085e3ef8d0336724`. Every
update must be signed with it, so back it up somewhere other than the build
machine. Never commit a keystore or its password.

`versionCode` is the branch's commit count, so each build installs over the
previous one. Override it with `-PversionCode=N`.

## Publish for new users

People without the app download it from the public `datum-download` bucket:
<https://datum-download.s3.us-east-2.amazonaws.com/connect/android/index.html>.

```sh
nix develop .#android
cd connect-mobile/android
export DATUM_CONNECT_SIGNING=~/.config/datum-connect/android-release/signing.properties
gradle assembleRelease
AWS_PROFILE=datum-admin scripts/publish-apk.sh
```

`publish-apk.sh` refuses debug-signed APKs. It uploads
`datum-connect-YYYYMMDD-<sha256[:12]>.apk` (build date in UTC) with its
version and full SHA-256 as object metadata, then replaces `index.html` and
`latest.json`, which point at the newest build. The page lists every earlier
APK in the bucket under "Past builds", newest first, using that metadata. APK
objects are immutable; the page and JSON are served with `no-cache`.

The bucket is in AWS account 007091975061, us-east-2. Block Public Access is
on except for a bucket policy that allows public `s3:GetObject`. ACLs are
disabled, objects are encrypted with SSE-S3, and listing and uploads are
denied to the public.

Once installed from the bucket, a phone takes updates only from release-signed
builds. Run `share-apk.sh` with `DATUM_CONNECT_SIGNING` set to share one.
