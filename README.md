# mosaic-zig

WIP Zig static library for the [Mosaic protocol](https://mikedilger.github.io/mosaic-spec/).

## Usage

```sh
zig build        # builds and installs libmosaic.a into zig-out/
zig build test   # runs unit tests
```

`nix run .#ci` mirrors the CI workflow locally (fmt, build, test).
