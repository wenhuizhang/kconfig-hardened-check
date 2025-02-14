######################################################
#                                                    #
# Some kernel configurations are available directly. #
#                                                    #
######################################################

Alpine Linux:
https://git.alpinelinux.org/aports/plain/main/linux-lts/config-lts.x86_64

Amazon Linux 2:
http://52.45.193.166/mirrors/http/amazonlinux.us-east-1.amazonaws.com/amazon_linux_2/?C=M;O=D

Arch Linux:
https://git.archlinux.org/svntogit/packages.git/plain/linux-hardened/trunk/config

Clear Linux OS:
https://raw.githubusercontent.com/clearlinux-pkgs/linux/master/config
https://raw.githubusercontent.com/clearlinux-pkgs/linux/master/cmdline

Oracle Linux: Unbreakable Enterprise Kernel (UEK):
https://raw.githubusercontent.com/oracle/linux-uek/uek6/master/uek-rpm/ol7/config-x86_64

SUSE Linux Enterprise (SLE):
https://kernel.opensuse.org/cgit/kernel-source/plain/config/x86_64/default?h=SLE15-SP2

openSUSE:
https://kernel.opensuse.org/cgit/kernel-source/plain/config/x86_64/default?h=openSUSE-15.1

Pentoo:
https://raw.githubusercontent.com/pentoo/pentoo-livecd/master/livecd/amd64/kernel/config-5.5.5

Debian Buster:
https://packages.debian.org/buster/amd64/linux-image-4.19.0-8-amd64/download

AOSP (the instruction for kernel config generation):
https://source.android.com/devices/tech/debug/kasan-kcov

CLIP OS:
https://docs.clip-os.org/clipos/kernel.html#configuration
https://github.com/clipos/src_platform_config-linux-hardware
https://github.com/clipos/products_clipos/blob/master/efiboot/configure.d/95_dracut.sh

NixOS:
run contrib/get-nix-kconfig.py from nix-shell to get the kernel configs

CBL-Mariner:
https://github.com/microsoft/CBL-Mariner/blob/1.0/SPECS/kernel/config
