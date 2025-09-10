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
        
        # Use rust-overlay to get nightly Rust with musl target
        rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" "rust-analyzer" ];
          targets = [ "x86_64-unknown-linux-musl" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain with nightly
            rustToolchain
            
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
            just
            
            # Code quality tools
            shellcheck
            nixpkgs-fmt
            
            # Utilities
            mold
            binutils
          ];
          
          # Environment variables for musl compilation
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
          CC_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
          CXX_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-g++";
          AR_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-ar";
          
          # Ensure we're using the Nix-provided Rust
          CARGO_HOME = "/tmp/.cargo-nix";
          RUSTUP_HOME = "/tmp/.rustup-nix";
          
          shellHook = ''
            echo "Hecate development environment loaded"
            echo "Rust toolchain: nightly (via rust-overlay)"
            rustc --version
            cargo --version
            echo "Run 'just' to see available commands"
          '';
        };
      });
}