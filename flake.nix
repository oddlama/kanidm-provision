{
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nci.url = "github:yusdacra/nix-cargo-integration";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [
        inputs.nci.flakeModule
        inputs.pre-commit-hooks.flakeModule

        # Derive the output overlay automatically from all packages that we define.
        inputs.flake-parts.flakeModules.easyOverlay
      ];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem = {
        config,
        pkgs,
        system,
        ...
      }: let
        projectName = "kanidm-provision";

        pkgsWithSelf = import inputs.nixpkgs {
          inherit system;
          overlays = [inputs.self.overlays.default];
        };
      in {
        pre-commit.settings.hooks = {
          alejandra.enable = true;
          deadnix.enable = true;
          statix.enable = true;
        };

        nci.projects.${projectName}.path = ./.;
        nci.crates.${projectName} = {};

        devShells.default = config.nci.outputs.${projectName}.devShell.overrideAttrs (old: {
          nativeBuildInputs =
            (old.nativeBuildInputs or [])
            ++ [
              pkgs.cargo-release
            ];

          shellHook = ''
            ${old.shellHook or ""}
            ${config.pre-commit.installationScript}
          '';
        });

        packages.default = config.nci.outputs.${projectName}.packages.release;
        # Offer to run the upstream tests with the current package for testing
        packages.test = pkgsWithSelf.nixosTests.kanidm-provisioning;

        formatter = pkgs.alejandra; # `nix fmt`
        overlayAttrs = {
          kanidm-provision = config.packages.default;
        };
      };
    };
}
