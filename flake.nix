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

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
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

      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:
        let
          projectName = "kanidm-provision";

          pkgsWithSelf = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.self.overlays.default ];
          };
        in
        {
          pre-commit.settings.hooks = {
            deadnix.enable = true;
            statix.enable = true;
            nixfmt = {
              enable = true;
              package = pkgs.nixfmt-rfc-style;
            };
          };

          nci.projects.${projectName}.path = ./.;
          nci.crates.${projectName} = { };

          devShells.default = config.nci.outputs.${projectName}.devShell.overrideAttrs (old: {
            nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.cargo-release ];

            shellHook = ''
              ${old.shellHook or ""}
              ${config.pre-commit.installationScript}
            '';
          });

          packages.default = config.nci.outputs.${projectName}.packages.release;
          packages.test = import ./tests/kanidm-provision.nix {
            pkgs = pkgsWithSelf;
            inherit (inputs) self;
          };

          formatter = pkgs.nixfmt-rfc-style; # `nix fmt`
          overlayAttrs = {
            kanidm-provision = config.packages.default;
          };
        };
    };
}
