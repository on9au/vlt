{
  description = "Rust project";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {nixpkgs, ...}: let
    forEachSystem = f:
      nixpkgs.lib.genAttrs ["aarch64-darwin" "x86_64-linux"]
      (system: f nixpkgs.legacyPackages.${system});
  in {
    devShells = forEachSystem (pkgs: {
      default = pkgs.mkShell {
        packages = with pkgs; [
          cargo
          clippy
          rust-analyzer
          rustc
          rustfmt
          taplo
        ];

        # nixpkgs' rustc carries no rust-src component, so rust-analyzer has
        # nowhere to read std from, no goto-definition or completion into it.
        # The login shell already exports this, but for the *system* rustc, so a
        # project on a different nixpkgs would read std from the wrong version.
        RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
      };
    });
  };
}
