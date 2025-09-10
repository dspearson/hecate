{
  description = "Hecate - Secure file archiving tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        
        # Rust toolchain configuration
        rustChannel = "nightly";
        
        # Library paths for linking
        libPath = with pkgs; lib.makeLibraryPath [
          libsodium
          zstd
          openssl
        ];
      in
      {
        devShells.default = pkgs.mkShell rec {
          buildInputs = with pkgs; [
            # Clang and LLVM for building
            clang
            llvmPackages_latest.bintools
            llvmPackages_latest.libclang.lib
            
            # Rustup for managing Rust toolchain
            rustup
            
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
            lld
            binutils
          ];
          
          RUSTC_VERSION = rustChannel;
          
          # Path for libclang (needed for bindgen)
          LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ pkgs.llvmPackages_latest.libclang.lib ];
          
          # Environment variables for musl compilation
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
          CC_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-gcc";
          CXX_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-g++";
          AR_x86_64_unknown_linux_musl = "${pkgs.pkgsCross.musl64.stdenv.cc}/bin/x86_64-unknown-linux-musl-ar";
          
          # Library paths for Rust
          RUSTFLAGS = (builtins.map (a: ''-L ${a}/lib'') [
            pkgs.libsodium
            pkgs.zstd
            pkgs.openssl
          ]);
          
          LD_LIBRARY_PATH = libPath;
          
          # Bindgen clang args for finding headers
          BINDGEN_EXTRA_CLANG_ARGS = 
            (builtins.map (a: ''-I"${a}/include"'') [
              pkgs.glibc.dev
              pkgs.libsodium.dev
              pkgs.zstd.dev
              pkgs.openssl.dev
            ])
            ++ [
              ''-I"${pkgs.llvmPackages_latest.libclang.lib}/lib/clang/${pkgs.llvmPackages_latest.libclang.version}/include"''
              ''-I"${pkgs.glib.dev}/include/glib-2.0"''
              ''-I${pkgs.glib.out}/lib/glib-2.0/include/''
            ];
          
          shellHook = ''
            export PATH=$PATH:''${CARGO_HOME:-~/.cargo}/bin
            export PATH=$PATH:''${RUSTUP_HOME:-~/.rustup}/toolchains/$RUSTC_VERSION-x86_64-unknown-linux-gnu/bin/
            
            # Install the toolchain if not present
            if ! rustup toolchain list | grep -q "$RUSTC_VERSION"; then
              echo "Installing Rust $RUSTC_VERSION toolchain..."
              rustup toolchain install $RUSTC_VERSION
              rustup component add rustfmt clippy rust-analyzer --toolchain $RUSTC_VERSION
              rustup target add x86_64-unknown-linux-musl --toolchain $RUSTC_VERSION
            fi
            
            # Set as default
            rustup default $RUSTC_VERSION
            
            echo "Hecate development environment loaded"
            echo "Rust toolchain: $RUSTC_VERSION"
            rustc --version
            cargo clippy --version
            echo "Run 'just' to see available commands"
          '';
        };
      });
}