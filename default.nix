{ pkgs ? (import <nixpkgs> {}) }:
with pkgs;

pkgs.python3.pkgs.buildPythonPackage {
  name = "kconfig-safety-check";
  src = ./.;
  SOURCE_DATE_EPOCH = "1523278946";
}
