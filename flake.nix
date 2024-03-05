{
  description = "A small utility to help with kanidm provisioning";
  inputs = {
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    self,
    advisory-db,
    devshell,
    crane,
    flake-utils,
    nixpkgs,
    pre-commit-hooks,
  }:
    flake-utils.lib.eachDefaultSystem (localSystem: let
      pkgs = import nixpkgs {
        inherit localSystem;
        overlays = [
          devshell.overlays.default
        ];
      };
      inherit (pkgs) lib;

      projectName = "kanidm-provision";
      craneLib = crane.lib.${localSystem};

      # For each of the classical cargo "functions" like build, doc, test, ...,
      # crane exposes a function that takes some configuration arguments.
      # Common settings that we need for all of these are grouped here.
      commonArgs = {
        src = craneLib.cleanCargoSource (craneLib.path ./.);

        # External packages required to compile this project.
        # For normal rust applications this would contain runtime dependencies,
        # but since we are compiling for a foreign platform this is most likely
        # going to stay empty except for the linker.
        buildInputs =
          [
            # Add additional build inputs here
          ]
          ++ lib.optionals pkgs.stdenv.isDarwin [
            # Additional darwin specific inputs can be set here
            pkgs.libiconv
          ];
      };

      # Build *just* the cargo dependencies, so we can reuse
      # all of that work (e.g. via cachix) when running in CI
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      # Build the actual package
      package = craneLib.buildPackage (commonArgs
        // {
          inherit cargoArtifacts;
        });
    in {
      # Define checks that can be run with `nix flake check`
      checks =
        {
          # Build the crate normally as part of checking, for convenience
          ${projectName} = package;

          # Run clippy (and deny all warnings) on the crate source,
          # again, resuing the dependency artifacts from above.
          #
          # Note that this is done as a separate derivation so that
          # we can block the CI if there are issues here, but not
          # prevent downstream consumers from building our crate by itself.
          "${projectName}-clippy" = craneLib.cargoClippy (commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            });

          "${projectName}-doc" = craneLib.cargoDoc (commonArgs
            // {
              inherit cargoArtifacts;
            });

          # Check formatting
          "${projectName}-fmt" = craneLib.cargoFmt {
            inherit (commonArgs) src;
          };

          # Audit dependencies
          "${projectName}-audit" = craneLib.cargoAudit {
            inherit (commonArgs) src;
            inherit advisory-db;
          };
        }
        // {
          pre-commit = pre-commit-hooks.lib.${localSystem}.run {
            src = ./.;
            hooks = {
              alejandra.enable = true;
              cargo-check.enable = true;
              rustfmt.enable = true;
              statix.enable = true;
            };
          };
        };

      packages.default = package; # `nix build`
      packages.${projectName} = package; # `nix build .#${projectName}`

      # `nix develop`
      devShells.default = pkgs.devshell.mkShell {
        name = projectName;
        imports = [
          "${devshell}/extra/language/c.nix"
          "${devshell}/extra/language/rust.nix"
        ];

        commands = [
          {
            package = pkgs.alejandra;
            help = "Format nix code";
          }
          {
            package = pkgs.statix;
            help = "Lint nix code";
          }
          {
            package = pkgs.deadnix;
            help = "Find unused expressions in nix code";
          }
        ];

        devshell.startup.pre-commit.text = self.checks.${localSystem}.pre-commit.shellHook;
        packages =
          commonArgs.buildInputs
          ++ [
            pkgs.rust-analyzer
          ];
      };

      formatter = pkgs.alejandra; # `nix fmt`
    });
}
