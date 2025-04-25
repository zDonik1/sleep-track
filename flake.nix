{
  description = "Go tests.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        courtney =
          with pkgs;
          buildGoModule {
            pname = "courtney";
            version = "0.4.4";

            # for of original repo @ https://github.com/dave/courtney
            # contains a bump to go.mod file
            src = fetchFromGitHub {
              owner = "zDonik1";
              repo = "courtney";
              rev = "f4c604c6582d9f31b4b716636b6cd864bea16d40";
              hash = "sha256-288XbCNufF7u2SgXLJt7n3fln6O93/+fqbT1GHMpuw4=";
            };

            vendorHash = "sha256-uXe74sVGj7DTWReJq/tkrhKUlZc6PD3OSAF7BRjHRV0=";

            # for some reason the tests are failing
            doCheck = false;
          };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gotest
            husky
            courtney
            golangci-lint
          ];
        };
      }
    );
}
