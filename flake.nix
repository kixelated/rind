{
  description = "rind - pure-Rust cryptography for MoQ";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The quest CLI, which also serves the quest guide and skills the stubs in
    # .claude/skills call. Bump the rev to upgrade them.
    quest = {
      url = "github:kixelated/quest/ed657ba9362a941b3be9bbea55120a3c5a90374c";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      quest,
      ...
    }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };

          # Pinned build toolchain so `nix develop` and CI compile against the
          # same rustc. The crates declare their own lower floors (rust-version),
          # which the MSRV job in lints.yml checks. No rust-toolchain.toml: it
          # would override the nightly, cranelift, and MSRV jobs' toolchains.
          rust-toolchain = pkgs.rust-bin.stable."1.98.1".minimal.override {
            # `minimal` rather than `default`, which adds offline HTML docs to
            # a closure every CI job downloads.
            extensions = [
              "rustfmt"
              "clippy"
              "rust-src"
              "rust-analyzer"
            ];
          };

          quest-cli = quest.packages.${system}.default;
        in
        {
          packages = {
            # The quest CLI alone, so quest.yml can validate the tree without
            # entering the dev shell.
            quest = quest-cli;
          };

          devShells.default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                rust-toolchain
                just
                git
                jq
                # aws-lc-rs (dev-dependency, the differential-test oracle),
                # libfuzzer-sys, and the OpenSSL benchmarks build C.
                cmake
                pkg-config
                openssl
                cargo-deny
                cargo-semver-checks
                # Linters used by `just check` and `just fix`, which skip a
                # module whose tools aren't on $PATH. CI sets CI_STRICT=1, which
                # turns that skip into an error (see sh/dispatch.sh).
                shellcheck
                actionlint
                nixfmt
                # admin/ scripts.
                python3
                quest-cli
              ]
              ++ pkgs.lib.optionals (!pkgs.stdenv.hostPlatform.isDarwin) [
                # Marked broken on Darwin in nixpkgs.
                release-plz
                # admin/ctgrind's constant-time checks.
                valgrind
              ];

            # What sh/dispatch.sh checks before a scoped `just check` or `just
            # fix`. IN_NIX_SHELL would also pass inside another project's shell.
            env.IN_RIND_DEV_SHELL = "1";
          };

          formatter = pkgs.nixfmt-tree;
        }
      );
}
