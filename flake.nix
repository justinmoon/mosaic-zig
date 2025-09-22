{
  description = "Mosaic Zig hello world executable";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    zig = {
      url = "github:mitchellh/zig-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, zig }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ zig.overlays.default ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        zigPkg = pkgs.zigpkgs."0.15.1"; # Keep toolchain pinned to Zig 0.15.1 for reproducibility.
        zlsPkg = pkgs.zls; # Ships Zig Language Server (0.15.0) from the same nixpkgs revision.
        cargoPkg = pkgs.cargo;
        dollar = "\$";
        ciScript = pkgs.writeShellScriptBin "mosaic-ci" ''
          set -euo pipefail
          cleanup_dir=""
          if [ -z "${dollar}{TMPDIR:-}" ]; then
            cleanup_dir="$(mktemp -d)"
            TMPDIR="$cleanup_dir"
            export TMPDIR
            trap 'rm -rf "$cleanup_dir"' EXIT
          fi
          export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-global-cache"
          export ZIG_LOCAL_CACHE_DIR="$ZIG_GLOBAL_CACHE_DIR"
          mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
          ${zigPkg}/bin/zig fmt --check build.zig build.zig.zon src
          ${zigPkg}/bin/zig build
          ${zigPkg}/bin/zig build test
          (cd test-vectors && ${cargoPkg}/bin/cargo check)
        '';
      in {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "mosaic-zig";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = [ zigPkg pkgs.pkg-config ];
          dontConfigure = true;
          buildPhase = ''
            export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global-cache
            export ZIG_LOCAL_CACHE_DIR=$TMPDIR/zig-cache
            ${zigPkg}/bin/zig build install --prefix $out -Doptimize=ReleaseSafe
          '';
          installPhase = "true";
          doCheck = true;
          checkPhase = ''
            export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global-cache
            export ZIG_LOCAL_CACHE_DIR=$TMPDIR/zig-cache
            ${zigPkg}/bin/zig build test
          '';
        };

        packages.zls = zlsPkg;

        devShells.default = pkgs.mkShell {
          buildInputs = [ zigPkg pkgs.pkg-config zlsPkg cargoPkg pkgs.rustc pkgs.clang pkgs.libclang pkgs.gcc-unwrapped ];
          shellHook = ''
            export ZIG_GLOBAL_CACHE_DIR=$PWD/.zig-cache
            export ZIG_LOCAL_CACHE_DIR=$ZIG_GLOBAL_CACHE_DIR
            export PATH="${zigPkg}/bin:$PATH"
            export ZLS_ZIG_EXE_PATH="${zigPkg}/bin/zig"
            echo "mosaic-zig dev shell with Zig ${zigPkg.version} + ZLS ${zlsPkg.version}"
          '';
        };

        apps.ci = {
          type = "app";
          program = "${ciScript}/bin/mosaic-ci"; # Provides `nix run .#ci` for local parity with CI.
        };
      }
    );
}
