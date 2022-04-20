# kconfig-safety-check



There are plenty of safety and security hardening options in the Linux kernel. 

This tool is to help with checking Linux Configurations.



## Supported microarchitectures

  - X86_64
  - X86_32
  - ARM64
  - ARM


## Installation

You can install the package:

```
pip install git+https://github.com/wenhuizhang/kconfig-safety-check
```

or simply run `./bin/kconfig-safety-check` from the cloned repository.

Some Linux distributions also provide `kconfig-safety-check` as a package.

## Usage

Example usage:
```
./bin/kconfig-safety-check -p X86_64 -c ../linux-image-bsk/.config -m show_fail
```

```
usage: kconfig-safety-check [-h] [--version] [-p {X86_64,X86_32,ARM64,ARM}]
                              [-c CONFIG]
                              [-m {verbose,json,show_ok,show_fail}]

A tool for checking the security hardening options of the Linux kernel

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print security hardening preferences for the selected architecture
  -c CONFIG, --config CONFIG
                        check the kernel config file against these preferences
  -m {verbose,json,show_ok,show_fail}, --mode {verbose,json,show_ok,show_fail}
                        choose the report mode
```

## Output modes

  -  no `-m` argument for the default output mode (see the example below)
  - `-m verbose` for printing additional info:
    - config options without a corresponding check
    - internals of complex checks
  - `-m show_fail` for showing only the failed checks
  - `-m show_ok` for showing only the successful checks
  - `-m json` for printing the results in JSON format (for combining `kconfig-safety-check` with other tools)

## Example output for `Debian GNU/Linux 9 (stretch)` kernel config
```
$ ./bin/kconfig-safety-check -p X86_64 -c ../linux-image-bsk/.config -m show_fail
[+] Special report mode: show_fail
[+] Kconfig file to check: ../linux-image-bsk/.config
[+] Detected architecture: X86_64
[+] Detected kernel version: 5.10
=========================================================================================================================
              option name               | type  |desired val | decision |      reason      | check result
=========================================================================================================================
CONFIG_CONFIG_SLAB_FREELIST_RANDOM      |kconfig|     y      |  elisa   |   elisa_safety   | FAIL: not found

[+] Config check is finished: 'OK' - 0 (suppressed in output) / 'FAIL' - 1
```



