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
        inherit (pkgs) mkShell stdenv;
        zigPkg = pkgs.zigpkgs."0.15.1"; # Keep toolchain pinned to Zig 0.15.1 for reproducibility.
        zlsPkg = pkgs.zls; # Ships Zig Language Server (0.15.0) from the same nixpkgs revision.
        cargoPkg = pkgs.cargo;
        zigBuildCacheEnv = ''
          export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global-cache
          export ZIG_LOCAL_CACHE_DIR=$TMPDIR/zig-cache
        '';
        ciScript = pkgs.writeShellApplication {
          name = "mosaic-ci";
          runtimeInputs = [ zigPkg cargoPkg pkgs.coreutils ];
          text = builtins.readFile ./scripts/ci.sh;
        };
      in {
        packages.default = stdenv.mkDerivation {
          pname = "mosaic-zig";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = [ zigPkg pkgs.pkg-config ];
          dontConfigure = true;
          buildPhase = zigBuildCacheEnv + ''
            ${zigPkg}/bin/zig build install --prefix $out -Doptimize=ReleaseSafe
          '';
          installPhase = "true";
          doCheck = true;
          checkPhase = zigBuildCacheEnv + ''
            ${zigPkg}/bin/zig build test
          '';
        };

        packages.zls = zlsPkg;

        devShells.default = mkShell {
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
