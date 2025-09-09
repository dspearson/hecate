{
  description = "Hecate - Secure file archiving tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "x86_64-unknown-linux-musl" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain with musl target
            rustToolchain

            # Build tools
            pkg-config
            cmake
            gcc

            # Musl toolchain
            musl
            musl.dev

            # Development tools
            cargo-edit
            cargo-watch
            cargo-audit

            # Code quality tools
            shellcheck
            nixpkgs-fmt

            # Utilities
            lld
            binutils
          ];

          # Environment variables for musl compilation using standard gcc
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "gcc";
          CC_x86_64_unknown_linux_musl = "gcc";
          CXX_x86_64_unknown_linux_musl = "g++";
          AR_x86_64_unknown_linux_musl = "ar";

          # Note: RUSTFLAGS for musl are set in .cargo/config.toml per target

          # Preserve existing environment variables
          MERCURY_AUTH_KEY = "21b01ca51867c87285812b24793abf4df96acd465f6ff3e2e33d38ee85f4b83d";
          HECATE_AUTH_KEY = "21b01ca51867c87285812b24793abf4df96acd465f6ff3e2e33d38ee85f4b83d";

          shellHook = ''
            echo "Hecate development environment"
            echo "Musl target enabled for static binary compilation"
            echo "Run './build-musl.sh' to build a static musl binary"
            echo "Run './build-glibc.sh' to build a standard glibc binary"
            
            # Export env vars for musl compilation
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=gcc
            export CC_x86_64_unknown_linux_musl=gcc
            export CXX_x86_64_unknown_linux_musl=g++
            export AR_x86_64_unknown_linux_musl=ar
          '';
        };
      });
}
