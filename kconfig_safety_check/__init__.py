#!/usr/bin/python3
#
# Linux kernel safety options checking
# Working on X86_64, ARM64, X86_32, and ARM.
# Based on ELISA: https://docs.google.com/spreadsheets/d/1oiOmWTr94M7vP3sisFyBMftHfXqi2Ogd_DqGEl_dlyQ/edit?userstoinvite=haipeng.zhang.saes@gmail.com&actionButton=1#gid=1056671864
#
# Author: Alexander Popov <alex.popov@linux.com>
#         Wenhui Zhang <wenhui.zhang@bytedance.com>
#



import sys
from argparse import ArgumentParser
from collections import OrderedDict
import re
import json
from .__about__ import __version__

TYPES_OF_CHECKS = ('kconfig', 'version')

class OptCheck:
    # Constructor without the 'expected' parameter is for option presence checks (any value is OK)
    def __init__(self, reason, decision, name, expected=None):
        if not reason or not decision or not name:
            sys.exit('[!] ERROR: invalid {} check for "{}"'.format(self.__class__.__name__, name))
        self.name = name
        self.expected = expected
        self.decision = decision
        self.reason = reason
        self.state = None
        self.result = None

    def check(self):
        # handle the option presence check
        if self.expected is None:
            if self.state is None:
                self.result = 'FAIL: not present'
            else:
                self.result = 'OK: is present'
            return

        # handle the option value check
        if self.expected == self.state:
            self.result = 'OK'
        elif self.state is None:
            if self.expected == 'is not set':
                self.result = 'OK: not found'
            else:
                self.result = 'FAIL: not found'
        else:
            self.result = 'FAIL: "' + self.state + '"'

    def table_print(self, _mode, with_results):
        if self.expected is None:
            expected = ''
        else:
            expected = self.expected
        print('{:<40}|{:^7}|{:^12}|{:^10}|{:^18}'.format(self.name, self.type, expected, self.decision, self.reason), end='')
        if with_results:
            print('| {}'.format(self.result), end='')


class KconfigCheck(OptCheck):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = 'CONFIG_' + self.name

    @property
    def type(self):
        return 'kconfig'

    def json_dump(self, with_results):
        dump = [self.name, self.type, self.expected, self.decision, self.reason]
        if with_results:
            dump.append(self.result)
        return dump


class VersionCheck:
    def __init__(self, ver_expected):
        self.ver_expected = ver_expected
        self.ver = ()
        self.result = None

    @property
    def type(self):
        return 'version'

    def check(self):
        if self.ver[0] > self.ver_expected[0]:
            self.result = 'OK: version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return
        if self.ver[0] < self.ver_expected[0]:
            self.result = 'FAIL: version < ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return
        if self.ver[1] >= self.ver_expected[1]:
            self.result = 'OK: version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return
        self.result = 'FAIL: version < ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])

    def table_print(self, _mode, with_results):
        ver_req = 'kernel version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
        print('{:<91}'.format(ver_req), end='')
        if with_results:
            print('| {}'.format(self.result), end='')


class ComplexOptCheck:
    def __init__(self, *opts):
        self.opts = opts
        if not self.opts:
            sys.exit('[!] ERROR: empty {} check'.format(self.__class__.__name__))
        if len(self.opts) == 1:
            sys.exit('[!] ERROR: useless {} check'.format(self.__class__.__name__))
        if not isinstance(opts[0], KconfigCheck):
            sys.exit('[!] ERROR: invalid {} check: {}'.format(self.__class__.__name__, opts))
        self.result = None

    @property
    def name(self):
        return self.opts[0].name

    @property
    def type(self):
        return 'complex'

    @property
    def expected(self):
        return self.opts[0].expected

    @property
    def decision(self):
        return self.opts[0].decision

    @property
    def reason(self):
        return self.opts[0].reason

    def table_print(self, mode, with_results):
        if mode == 'verbose':
            print('    {:87}'.format('<<< ' + self.__class__.__name__ + ' >>>'), end='')
            if with_results:
                print('| {}'.format(self.result), end='')
            for o in self.opts:
                print()
                o.table_print(mode, with_results)
        else:
            o = self.opts[0]
            o.table_print(mode, False)
            if with_results:
                print('| {}'.format(self.result), end='')

    def json_dump(self, with_results):
        dump = self.opts[0].json_dump(False)
        if with_results:
            dump.append(self.result)
        return dump


class OR(ComplexOptCheck):
    # self.opts[0] is the option that this OR-check is about.
    # Use cases:
    #     OR(<X_is_safety>, <X_is_disabled>)
    #     OR(<X_is_safety>, <old_X_is_safety>)
    def check(self):
        if not self.opts:
            sys.exit('[!] ERROR: invalid OR check')
        for i, opt in enumerate(self.opts):
            opt.check()
            if opt.result.startswith('OK'):
                self.result = opt.result
                # Add more info for additional checks:
                if i != 0:
                    if opt.result == 'OK':
                        self.result = 'OK: {} "{}"'.format(opt.name, opt.expected)
                    elif opt.result == 'OK: not found':
                        self.result = 'OK: {} not found'.format(opt.name)
                    elif opt.result == 'OK: is present':
                        self.result = 'OK: {} is present'.format(opt.name)
                    # VersionCheck provides enough info
                    elif not opt.result.startswith('OK: version'):
                        sys.exit('[!] ERROR: unexpected OK description "{}"'.format(opt.result))
                return
        self.result = self.opts[0].result


class AND(ComplexOptCheck):
    # self.opts[0] is the option that this AND-check is about.
    # Use cases:
    #     AND(<suboption>, <main_option>)
    #       Suboption is not checked if checking of the main_option is failed.
    #     AND(<X_is_disabled>, <old_X_is_disabled>)
    def check(self):
        for i, opt in reversed(list(enumerate(self.opts))):
            opt.check()
            if i == 0:
                self.result = opt.result
                return
            if not opt.result.startswith('OK'):
                # This FAIL is caused by additional checks,
                # and not by the main option that this AND-check is about.
                # Describe the reason of the FAIL.
                if opt.result.startswith('FAIL: \"') or opt.result == 'FAIL: not found':
                    self.result = 'FAIL: {} not "{}"'.format(opt.name, opt.expected)
                elif opt.result == 'FAIL: not present':
                    self.result = 'FAIL: {} not present'.format(opt.name)
                else:
                    # VersionCheck provides enough info
                    self.result = opt.result
                    if not opt.result.startswith('FAIL: version'):
                        sys.exit('[!] ERROR: unexpected FAIL description "{}"'.format(opt.result))
                return
        sys.exit('[!] ERROR: invalid AND check')


def detect_arch(fname, archs):
    with open(fname, 'r') as f:
        arch_pattern = re.compile("CONFIG_[a-zA-Z0-9_]*=y")
        arch = None
        for line in f.readlines():
            if arch_pattern.match(line):
                option, _ = line[7:].split('=', 1)
                if option in archs:
                    if not arch:
                        arch = option
                    else:
                        return None, 'more than one supported architecture is detected'
        if not arch:
            return None, 'failed to detect architecture'
        return arch, 'OK'


def detect_version(fname):
    with open(fname, 'r') as f:
        ver_pattern = re.compile("# Linux/.* Kernel Configuration")
        for line in f.readlines():
            if ver_pattern.match(line):
                line = line.strip()
                parts = line.split()
                ver_str = parts[2]
                ver_numbers = ver_str.split('.')
                if len(ver_numbers) < 3 or not ver_numbers[0].isdigit() or not ver_numbers[1].isdigit():
                    msg = 'failed to parse the version "' + ver_str + '"'
                    return None, msg
                return (int(ver_numbers[0]), int(ver_numbers[1])), None
        return None, 'no kernel version detected'


def add_kconfig_checks(l, arch):
    # Calling the KconfigCheck class constructor:
    #     KconfigCheck(reason, decision, name, expected)

    # elisa safety check
    l += [KconfigCheck('elisa_safety', 'elisa', 'SLAB_FREELIST_RANDOM', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'SLAB_FREELIST_HARDENED', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'SLAB_MERGE_DEFAULT', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'SHUFFLE_PAGE_ALLOCATOR', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'SLUB_DEBUG', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'INIT_ON_FREE_DEFAULT_ON', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'INIT_ON_ALLOC_DEFAULT_ON', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'REFCOUNT_FULL', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'GCC_PLUGIN_STRUCTKLEAK', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'GCC_PLUGIN_STRUCTLEAK_BYREF_ALL', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'INIT_STACK_ALL', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'BPF_JIT_ALWAYS_ON', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'BPF_UNPRIV_DEFAULT_OFF', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'STACKPROTECTOR', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'STACKPROTECTOR_STRONG', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'FORTIFY_SOURCE', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'SCHED_STACK_END_CHECK', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'VMAP_STACK', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'THREAD_INFO_IN_TASK', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'GCC_PLUGIN_STACKLEAK', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'PAGE_POISONING', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'PAGE_POISONING_NO_SANITY', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_LIST', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_SG', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'BUG_ON_DATA_CORRUPTION', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEVMEM', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEVPORT', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'ACPI_CUSTOM_METHOD', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'LEGACY_PTYS', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'HIBERNATION', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'KEXEC', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'HARDENED_USERCOPY', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'HARDENED_USERCOPY_FALLBACK', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'HARDENED_USERCOPY_PAGESPAN', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'SECURITY_DMESG_RESTRICT', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'COMPAT_BRK', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'USERFAULTFD', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'STRICT_KERNEL_RWX', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'STRICT_MODULE_RWX', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_WX', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'STACKTRACE_SUPPORT', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'STACK_TRACER', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'KPROBES', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'PROC_KCORE', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'ELF_CORE', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'PROC_PAGE_MONITOR', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'FTRACE_SYSCALLS', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'KALLSYMS', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'SOFTLOCKUP_DETECTOR', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DETECT_HUNG_TASK', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'WQ_WATCHDOG', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'KCSAN', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'PROVE_LOCKING', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_RT_MUTEXES', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_NOTIFIERS', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'LOCK_STAT', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_SPINLOCK', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_MUTEXES', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_WW_MUTEX_SLOWPATH', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_LOCK_ALLOC', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_LOCKING_API_SELFTESTS', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'LOCK_TORTURE_TEST', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'WW_MUTEX_SELFTEST', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'RCU_TORTURE_TEST', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'DEBUG_ATOMIC_SLEEP', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'SIGNALFD', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'RETPOLINE', 'y')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'BPF_UNPRIV_DEFAULT_OFF', 'n')]
    l += [KconfigCheck('elisa_safety', 'elisa', 'LIVEPATCH', 'n')]


    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('elisa_safety', 'elisa', 'DEVKMEM', 'y')]
        l += [KconfigCheck('elisa_safety', 'elisa', 'PAGE_TABLE_ISOLATION', 'y')]
    if arch in ('ARM', 'ARM64'):
        l += [KconfigCheck('elisa_safety', 'elisa', 'UNMAP_KERNEL_AT_EL0', 'y')]
        l += [KconfigCheck('elisa_safety', 'elisa', 'HARDEN_BRANCH_PREDICTOR', 'y')]
        l += [KconfigCheck('elisa_safety', 'elisa', 'HARDEN_EL2_VECTORS', 'y')]
        l += [KconfigCheck('elisa_safety', 'elisa', 'ARM64_SSBD', 'y')]



def print_unknown_options(checklist, parsed_options):
    known_options = []

    for o1 in checklist:
        if o1.type != 'complex':
            known_options.append(o1.name)
            continue
        for o2 in o1.opts:
            if o2.type != 'complex':
                if hasattr(o2, 'name'):
                    known_options.append(o2.name)
                continue
            for o3 in o2.opts:
                if o3.type == 'complex':
                    sys.exit('[!] ERROR: unexpected ComplexOptCheck inside {}'.format(o2.name))
                if hasattr(o3, 'name'):
                    known_options.append(o3.name)

    for option, value in parsed_options.items():
        if option not in known_options:
            print('[?] No check for option {} ({})'.format(option, value))


def print_checklist(mode, checklist, with_results):
    if mode == 'json':
        output = []
        for o in checklist:
            output.append(o.json_dump(with_results))
        print(json.dumps(output))
        return

    # table header
    sep_line_len = 91
    if with_results:
        sep_line_len += 30
    print('=' * sep_line_len)
    print('{:^40}|{:^7}|{:^12}|{:^10}|{:^18}'.format('option name', 'type', 'desired val', 'decision', 'reason'), end='')
    if with_results:
        print('| {}'.format('check result'), end='')
    print()
    print('=' * sep_line_len)

    # table contents
    for opt in checklist:
        if with_results:
            if mode == 'show_ok':
                if not opt.result.startswith('OK'):
                    continue
            if mode == 'show_fail':
                if not opt.result.startswith('FAIL'):
                    continue
        opt.table_print(mode, with_results)
        print()
        if mode == 'verbose':
            print('-' * sep_line_len)
    print()

    # final score
    if with_results:
        fail_count = len(list(filter(lambda opt: opt.result.startswith('FAIL'), checklist)))
        fail_suppressed = ''
        ok_count = len(list(filter(lambda opt: opt.result.startswith('OK'), checklist)))
        ok_suppressed = ''
        if mode == 'show_ok':
            fail_suppressed = ' (suppressed in output)'
        if mode == 'show_fail':
            ok_suppressed = ' (suppressed in output)'
        if mode != 'json':
            print('[+] Config check is finished: \'OK\' - {}{} / \'FAIL\' - {}{}'.format(ok_count, ok_suppressed, fail_count, fail_suppressed))


def populate_simple_opt_with_data(opt, data, data_type):
    if opt.type == 'complex':
        sys.exit('[!] ERROR: unexpected ComplexOptCheck {}: {}'.format(opt.name, vars(opt)))
    if data_type not in TYPES_OF_CHECKS:
        sys.exit('[!] ERROR: invalid data type "{}"'.format(data_type))

    if data_type != opt.type:
        return

    if data_type == 'kconfig':
        opt.state = data.get(opt.name, None)
    elif data_type == 'version':
        opt.ver = data
    else:
        sys.exit('[!] ERROR: unexpected data type "{}"'.format(data_type))


def populate_opt_with_data(opt, data, data_type):
    if opt.type == 'complex':
        for o in opt.opts:
            if o.type == 'complex':
                # Recursion for nested ComplexOptCheck objects
                populate_opt_with_data(o, data, data_type)
            else:
                populate_simple_opt_with_data(o, data, data_type)
    else:
        if opt.type != 'kconfig':
            sys.exit('[!] ERROR: bad type "{}" for a simple check {}'.format(opt.type, opt.name))
        populate_simple_opt_with_data(opt, data, data_type)


def populate_with_data(checklist, data, data_type):
    for opt in checklist:
        populate_opt_with_data(opt, data, data_type)


def perform_checks(checklist):
    for opt in checklist:
        opt.check()


def parse_kconfig_file(parsed_options, fname):
    with open(fname, 'r') as f:
        opt_is_on = re.compile("CONFIG_[a-zA-Z0-9_]*=[a-zA-Z0-9_\"]*")
        opt_is_off = re.compile("# CONFIG_[a-zA-Z0-9_]* is not set")

        for line in f.readlines():
            line = line.strip()
            option = None
            value = None

            if opt_is_on.match(line):
                option, value = line.split('=', 1)
            elif opt_is_off.match(line):
                option, value = line[2:].split(' ', 1)
                if value != 'is not set':
                    sys.exit('[!] ERROR: bad disabled kconfig option "{}"'.format(line))

            if option in parsed_options:
                sys.exit('[!] ERROR: kconfig option "{}" exists multiple times'.format(line))

            if option:
                parsed_options[option] = value


def main():
    # Report modes:
    #   * verbose mode for
    #     - reporting about unknown kernel options in the kconfig
    #     - verbose printing of ComplexOptCheck items
    #   * json mode for printing the results in JSON format
    report_modes = ['verbose', 'json', 'show_ok', 'show_fail']
    supported_archs = ['X86_64', 'X86_32', 'ARM64', 'ARM']
    parser = ArgumentParser(prog='kconfig-safety-check',
                            description='A tool for checking safety options of the Linux kernel')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-p', '--print', choices=supported_archs,
                        help='print safety preferences for the selected architecture')
    parser.add_argument('-c', '--config',
                        help='check the kernel kconfig file against these preferences')
    parser.add_argument('-m', '--mode', choices=report_modes,
                        help='choose the report mode')
    args = parser.parse_args()

    mode = None
    if args.mode:
        mode = args.mode
        if mode != 'json':
            print('[+] Special report mode: {}'.format(mode))

    config_checklist = []

    if args.config:
        if mode != 'json':
            print('[+] Kconfig file to check: {}'.format(args.config))

        arch, msg = detect_arch(args.config, supported_archs)
        if not arch:
            sys.exit('[!] ERROR: {}'.format(msg))
        if mode != 'json':
            print('[+] Detected architecture: {}'.format(arch))

        kernel_version, msg = detect_version(args.config)
        if not kernel_version:
            sys.exit('[!] ERROR: {}'.format(msg))
        if mode != 'json':
            print('[+] Detected kernel version: {}.{}'.format(kernel_version[0], kernel_version[1]))

        # add relevant kconfig checks to the checklist
        add_kconfig_checks(config_checklist, arch)

        # populate the checklist with the parsed kconfig data
        parsed_kconfig_options = OrderedDict()
        parse_kconfig_file(parsed_kconfig_options, args.config)
        populate_with_data(config_checklist, parsed_kconfig_options, 'kconfig')
        populate_with_data(config_checklist, kernel_version, 'version')

        # now everything is ready for performing the checks
        perform_checks(config_checklist)

        # finally print the results
        if mode == 'verbose':
            print_unknown_options(config_checklist, parsed_kconfig_options)
        print_checklist(mode, config_checklist, True)

        sys.exit(0)

    if args.print:
        if mode in ('show_ok', 'show_fail'):
            sys.exit('[!] ERROR: wrong mode "{}" for --print'.format(mode))
        arch = args.print
        add_kconfig_checks(config_checklist, arch)
        if mode != 'json':
            print('[+] Printing kernel safety configuration preferences for {}...'.format(arch))
        print_checklist(mode, config_checklist, False)
        sys.exit(0)

    parser.print_help()
    sys.exit(0)

if __name__ == '__main__':
    main()
