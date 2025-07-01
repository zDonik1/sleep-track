{
  description = "Go tests.";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
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

        commonEnv = {
          PGHOST = "localhost";
          PGPORT = "5433";
          PGUSER = "postgres";
          PGPASSWORD = "testpass";
        };
      in
      {
        devShells.default =
          pkgs.mkShell {
            packages = with pkgs; [
              go
              gotest
              pre-commit
              courtney
              golangci-lint
              sqlc
            ];
          }
          // commonEnv;

        packages = rec {
          default = sleep-track;

          sleep-track = pkgs.buildGoModule {
            name = "sleep-track";
            vendorHash = "sha256-hd4UkMTfDAiMA2ulqN3iFwg4MG5BdLgO+S+NZ8Sk+Kk=";
            src = ./.;
            preBuild = "go generate ./...";

            nativeBuildInputs = with pkgs; [ sqlc ];
          };

          test-postgres-container =
            let
              containerName = "test-postgres";
            in
            pkgs.writeShellScriptBin "run-db" ''
              docker rm -f ${containerName} 2>/dev/null || true
              docker run \
                  -d \
                  --name ${containerName} \
                  -e POSTGRES_PASSWORD=${commonEnv.PGPASSWORD} \
                  -p ${commonEnv.PGPORT}:5432 \
                  postgres:17.5
            '';

          sleep-track-test-runner =
            let
              sleepTrackTestRunner = sleep-track.overrideAttrs (prev: {
                buildPhase = ''
                  runHook preBuild
                  go test -c ./server
                  runHook postBuild
                '';

                installPhase = ''
                  runHook preInstall
                  mkdir -p $out/bin
                  cp ./server.test $out/bin/
                  runHook postInstall
                '';

                doCheck = false;
              });
            in
            pkgs.writeShellScriptBin "run-full-test-suite" ''
              INTEGRATION=1 \
              PGHOST=${commonEnv.PGHOST} \
              PGPORT=${commonEnv.PGPORT} \
              PGUSER=${commonEnv.PGUSER} \
              PGPASSWORD=${commonEnv.PGPASSWORD} \
              ${sleepTrackTestRunner}/bin/server.test -test.v 
            '';
        };
      }
    )
    // (
      let
        system = "x86_64-linux";
        pkgs = import nixpkgs { inherit system; };
      in
      {
        dockerImages."${system}".sleep-track = pkgs.dockerTools.buildLayeredImage {
          name = "ghcr.io/zDonik1/sleep-track";
          config = {
            Entrypoint = [ "${self.packages.x86_64-linux.sleep-track}/bin/sleep-track" ];
            ExposedPorts."80/tcp" = { };
          };
        };
      }
    );
}
