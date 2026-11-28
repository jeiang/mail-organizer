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
        buildInputs = [pkgs.sqlite];
        meta = {
          description = "Files IMAP mail into folders by rules and learned patterns";
          mainProgram = "mail-organizer";
        };
      };
  in {
    packages = forAllSystems (pkgs: {default = package pkgs;});

    devShells = forAllSystems (pkgs: {
      default = pkgs.mkShell {
        packages = with pkgs; [cargo rustc clippy rustfmt rust-analyzer sqlite sqlcipher prometheus.cli jq];
      };
    });

    nixosModules.default = import ./nix/module.nix self;

    # The package build runs `cargo test` in its check phase.
    checks = forAllSystems (pkgs:
      {
        package = package pkgs;
      }
      // nixpkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
        # Evaluates the module with two accounts and validates the rendered config.
        module = let
          system = nixpkgs.lib.nixosSystem {
            inherit (pkgs.stdenv.hostPlatform) system;
            modules = [
              self.nixosModules.default
              {
                boot.loader.grub.enable = false;
                fileSystems."/" = {
                  device = "none";
                  fsType = "tmpfs";
                };
                system.stateVersion = "25.11";
                services.mail-organizer = {
                  enable = true;
                  telemetry.enable = true;
                  llm.url = "http://127.0.0.1:8491";
                  accounts.icloud = {
                    preset = "icloud";
                    login = "a@example.com";
                    passwordFile = "/run/secrets/icloud";
                  };
                  accounts.gmail = {
                    preset = "gmail";
                    login = "b@example.com";
                    passwordFile = "/run/secrets/gmail";
                  };
                };
              }
            ];
          };
          inherit (system.config.systemd.services.mail-organizer) serviceConfig;
        in
          pkgs.runCommand "mail-organizer-module" {} ''
            cp ${system.config.environment.etc."mail-organizer/config.toml".source} config.toml
            sed -i 's|/var/lib/mail-organizer/mail.db|'"$PWD"'/mail.db|' config.toml
            ${pkgs.lib.getExe (package pkgs)} --config config.toml mode
            test ${toString (builtins.length serviceConfig.LoadCredential)} = 2
            touch $out
          '';
      });
  };
}
