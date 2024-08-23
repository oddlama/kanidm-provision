test:
{ pkgs, self }:
let
  inherit (pkgs) lib;
  nixos-lib = import (pkgs.path + "/nixos/lib") { };
  testRunner = nixos-lib.runTest {
    hostPkgs = pkgs;
    # Skip evaluating the documentation to speed up the testing
    defaults.documentation.enable = lib.mkDefault false;
    # Allow access to our flake
    node.specialArgs = {
      inherit self;
    };
    imports = [ test ];
  };
in
testRunner.config.result
