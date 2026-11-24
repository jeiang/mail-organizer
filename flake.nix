{
  description = "mail-organizer: files IMAP mail into folders by rules and learned patterns";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

    package = pkgs:
      pkgs.rustPlatform.buildRustPackage {
        pname = "mail-organizer";
        version = "0.1.0";
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [./Cargo.toml ./Cargo.lock ./src ./schema];
        };
        cargoLock.lockFile = ./Cargo.lock;
        meta = {
          description = "Files IMAP mail into folders by rules and learned patterns";
          mainProgram = "mail-organizer";
        };
      };
  in {
    packages = forAllSystems (pkgs: {default = package pkgs;});

    devShells = forAllSystems (pkgs: {
      default = pkgs.mkShell {
        packages = with pkgs; [cargo rustc clippy rustfmt rust-analyzer sqlite sqlcipher prometheus jq];
      };
    });

    nixosModules.default = import ./nix/module.nix self;

    # The package build runs `cargo test` in its check phase.
    checks = forAllSystems (pkgs: {
      package = package pkgs;
    });
  };
}
