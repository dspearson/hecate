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

        # Use rust-overlay to get Rust with musl target
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [ "x86_64-unknown-linux-musl" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain with musl target
            rustToolchain
            rust-analyzer

            # Build tools
            pkg-config
            cmake
            gcc
            
            # Native dependencies
            libsodium
            zstd
            openssl

            # Musl toolchain for static linking
            musl
            musl.dev
            pkgsCross.musl64.stdenv.cc

            # Development tools
            cargo-edit
            cargo-watch
            cargo-audit
            just

            # Code quality tools
            shellcheck
            nixpkgs-fmt

            # Utilities
            lld
            binutils
          ];

          # Environment variables for musl compilation
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
          CC_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
          CXX_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-g++";
          AR_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-ar";

          # Note: RUSTFLAGS for musl are set in .cargo/config.toml per target
          
          # Fix proc-macro linking by ensuring glibc is linked properly
          NIX_LDFLAGS = "-L${pkgs.glibc}/lib";
          CARGO_BUILD_RUSTFLAGS = "-C link-arg=-Wl,-rpath,${pkgs.glibc}/lib";

          shellHook = ''
            echo "Hecate development environment loaded"
            echo "Run 'just' to see available commands"
          '';
        };
      });
}
