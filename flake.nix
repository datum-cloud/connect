{
  description = "Datum Connect — Rust daemon and flat datumctl plugin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Pinned to match connect-lib/rust-toolchain.toml. The plugin Rust binary only
        # builds for the native host target. The tag-triggered release workflow
        # installs each explicit cross target for its build matrix.
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./connect-lib/rust-toolchain.toml;
        # On a Mac the dev shell also carries both Apple targets, so
        # scripts/build-macos-share.sh builds arm64 and x86_64 inside it.
        devRustToolchain =
          if pkgs.stdenv.isDarwin then
            rustToolchain.override {
              targets = [ "aarch64-apple-darwin" "x86_64-apple-darwin" ];
            }
          else
            rustToolchain;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        # Native build inputs (tools needed at build time).
        nativeBuildInputs = with pkgs; [
          pkg-config
        ];

        # Build inputs (libraries linked against).
        # openssl is needed by openssl-sys (transitive via reqwest in
        # connect-lib). libiconv is required on darwin.
        buildInputs = with pkgs; [
          openssl
        ] ++ lib.optionals stdenv.isDarwin [
          libiconv
        ];

      in
      {
        # ── Packaged Rust binary ──────────────────────────────────────────
        # `nix build` produces the persistent daemon. The Go CLI talks to its API.
        packages.default = rustPlatform.buildRustPackage {
          pname = "datum-connectd";
          version = "0.1.0";
          src = ./connect-lib;

          cargoLock = {
            lockFile = ./connect-lib/Cargo.lock;
            # Git dependencies need a fixed hash; update it when the rev in
            # Cargo.lock changes (nix build prints the new one).
            outputHashes = {
              "h3-0.0.8" = "sha256-vgyUL3kht0or68fhT5Uv6qp9Eg7TZU4UG2QfLrIXonQ=";
            };
          };

          inherit nativeBuildInputs buildInputs;

          cargoBuildFlags = [ "-p" "datum-connect-daemon" ];
          doCheck = true;
          cargoTestFlags = [ "--workspace" "--locked" ];
          # The sandbox has no system CA store, and building a reqwest client
          # fails without one.
          SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
          # This test hands the daemon /bin/sh as a helper that must be owned
          # by the build user or root. In the sandbox's user namespace the
          # root-owned store path shows up as owned by nobody, so it can't
          # pass here; cargo test covers it.
          checkFlags = [ "--skip=oidc_session_enrollment_pins_session_and_requires_setup_to_replace" ];

          meta = with pkgs.lib; {
            description = "Persistent Datum Connect daemon";
            homepage = "https://github.com/datum-cloud/datumctl-plugins";
            license = licenses.agpl3Only;
            mainProgram = "datum-connectd";
          };
        };

        # ── Development shell ─────────────────────────────────────────────
        # Use via `nix develop` from this directory (or `nix develop
        # path:./connect` from the workspace root). Provides Rust + Go +
        # task + pkg-config + openssl, with PKG_CONFIG_PATH set so
        # openssl-sys finds its lib via pkg-config out of the box.
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            # Rust toolchain (stable, with clippy + rustfmt + rust-analyzer)
            devRustToolchain

            # Go toolchain for the datumctl-connect plugin shell.
            # Pinned to match the directive in go.mod (currently 1.25.x);
            # nixpkgs unstable's `go` is the active stable Go release.
            go

            # Task runner — Taskfile.yaml at connect root is the canonical
            # entry point for build / test / install workflows.
            go-task

            # Common build tools
            pkg-config
            openssl

            # Useful dev utilities
            git
          ] ++ lib.optionals stdenv.isDarwin [ libiconv ];

          # openssl-sys reads OpenSSL paths from pkg-config. nixpkgs splits
          # openssl into `out` (libs) and `dev` (headers + .pc files); the
          # latter is what pkg-config needs to be pointed at.
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";

          # rust-analyzer wants this to navigate to std/core sources.
          RUST_SRC_PATH = "${devRustToolchain}/lib/rustlib/src/rust/library";

          shellHook = "";
        };

        # ── Android shell ─────────────────────────────────────────────────
        # `nix develop .#android` for connect-mobile/android: the Rust
        # toolchain with Android targets, cargo-ndk, the Android SDK and NDK,
        # JDK 17, and Gradle. The SDK is unfree; this shell accepts its license.
        devShells.android =
          let
            androidPkgs = import nixpkgs {
              inherit system overlays;
              config = {
                allowUnfree = true;
                android_sdk.accept_license = true;
              };
            };
            androidRust = rustToolchain.override {
              targets = [
                "aarch64-linux-android"
                "armv7-linux-androideabi"
                "x86_64-linux-android"
              ];
            };
            android = androidPkgs.androidenv.composeAndroidPackages {
              platformVersions = [ "35" ];
              buildToolsVersions = [ "35.0.0" ];
              includeNDK = true;
              ndkVersions = [ "27.2.12479018" ];
              includeEmulator = true;
              includeSystemImages = true;
              systemImageTypes = [ "google_apis" ];
              abiVersions = [ "x86_64" ];
            };
            sdkRoot = "${android.androidsdk}/libexec/android-sdk";
          in
          androidPkgs.mkShell {
            packages = [
              androidRust
              android.androidsdk
              androidPkgs.cargo-ndk
              androidPkgs.jdk17
              androidPkgs.gradle
            ];
            ANDROID_HOME = sdkRoot;
            ANDROID_SDK_ROOT = sdkRoot;
            ANDROID_NDK_ROOT = "${sdkRoot}/ndk/27.2.12479018";
            JAVA_HOME = androidPkgs.jdk17.home;
            # Gradle's downloaded aapt2 does not run from the Nix store layout;
            # use the SDK's.
            GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdkRoot}/build-tools/35.0.0/aapt2";
          };

        # nix fmt
        formatter = pkgs.nixpkgs-fmt;
      });
}
