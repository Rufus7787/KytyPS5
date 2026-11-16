#!/usr/bin/env python3
"""Names a live `prof` capture with the build's lld-link map, on any OS (profreport.exe needs the running process).

    prof-map.py PROF MAP [--modules MODULES] [--top 40] [--focus TEXT]

PROF: the file the live command `prof <seconds> <path>` wrote (16 64-bit words a sample: pc, the word at rsp, then up
to 14 frame-pointer return addresses; Windows samples wall time, so waits are samples too). MAP: the
kyty_emulator*.map of the same exe (the release workflow's "-symbols" artifact; the exe links at 0x140000000).
MODULES (optional): "base size name" lines (hex) of the process's DLLs, so frames outside the exe get a module name:
    Get-Process kyty_emulator | % Modules | % { '{0:x} {1:x} {2}' -f $_.BaseAddress.ToInt64(), $_.ModuleMemorySize, $_.ModuleName } > modules.txt
Prints self time, self time of the busy samples, inclusive time of the busy samples, and who waits (a sample whose
leaf is in ntdll/win32u/kernelbase or a GPU driver counts as waiting; without MODULES: any leaf outside the exe).
--focus TEXT: the callers (two emulator frames) of every leaf whose name contains TEXT.
"""
import argparse
import bisect
import collections
import re
import struct
import sys

BASE = 0x140000000
GUEST = (0x800000000, 0x1000000000)
WAIT_MODULES = ('ntdll', 'win32u', 'kernelbase', 'kernel32', 'nvoglv64', 'nvgpucomp64', 'amdvlk64', 'vulkan-1')


def load_map(path):
    rvas, names = [], []
    pattern = re.compile(r'^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\d+)\s+(.+?)\s*$')
    with open(path, encoding='utf-8', errors='replace') as file:
        for line in file:
            match = pattern.match(line)
            # Symbol lines have size 0 and alignment 0 (sections and object files have both set).
            if not match or int(match.group(2), 16) != 0 or match.group(3) != '0':
                continue
            rvas.append(int(match.group(1), 16))
            names.append(clean(match.group(4)))
    order = sorted(range(len(rvas)), key=rvas.__getitem__)
    return [rvas[i] for i in order], [names[i] for i in order]


def clean(name):
    for prefix in ('public: ', 'private: ', 'protected: ', 'static ', 'virtual '):
        while name.startswith(prefix):
            name = name[len(prefix):]
    if '__cdecl ' in name:
        name = name.split('__cdecl ', 1)[1]
    name = re.sub(r'\(.*$', '', name)
    for namespace in ('Kyty::', 'Libs::Graphics::', 'Libs::LibKernel::', 'Libs::'):
        name = name.replace(namespace, '')
    return name[:110]


def load_modules(path):
    modules = []
    with open(path, encoding='utf-8-sig', errors='replace') as file:
        for line in file:
            parts = line.split(None, 2)
            if len(parts) == 3:
                modules.append((int(parts[0], 16), int(parts[1], 16), parts[2].strip()))
    return sorted(modules)


class Namer:
    def __init__(self, rvas, names, modules):
        self.rvas, self.names, self.modules, self.cache = rvas, names, modules, {}
        self.exe_end = BASE + (rvas[-1] + 0x200000 if rvas else 0x2000000)

    def __call__(self, address):
        name = self.cache.get(address)
        if name is None:
            name = self.cache[address] = self.lookup(address)
        return name

    def lookup(self, address):
        if self.rvas and BASE + self.rvas[0] <= address < self.exe_end:
            i = bisect.bisect_right(self.rvas, address - BASE) - 1
            if i >= 0:
                return 'kyty!' + self.names[i]
        if GUEST[0] <= address < GUEST[1]:
            return 'guest-code'
        for base, size, module in self.modules:
            if base <= address < base + size:
                return module.lower().replace('.dll', '') + '!?'
        return '?'


def is_wait(name, have_modules):
    if name.startswith('kyty!') or name == 'guest-code':
        return False
    if not have_modules:
        return name == '?'
    return name.split('!', 1)[0] in WAIT_MODULES


def table(title, counts, total, top):
    print(f'\n== {title} ({total} samples) ==')
    for name, n in counts.most_common(top):
        print(f'{100.0 * n / max(total, 1):6.2f}%  {n:7d}  {name}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('prof')
    parser.add_argument('map')
    parser.add_argument('--modules')
    parser.add_argument('--top', type=int, default=40)
    parser.add_argument('--focus')
    args = parser.parse_args()

    rvas, names = load_map(args.map)
    if not rvas:
        sys.exit(f'no symbols read from {args.map}')
    modules = load_modules(args.modules) if args.modules else []
    name = Namer(rvas, names, modules)
    data = open(args.prof, 'rb').read()
    count = len(data) // 128
    samples = [struct.unpack_from('<16Q', data, i * 128) for i in range(count)]
    print(f'{count} samples (4 kHz: {count / 4000.0:.1f} s), {len(rvas)} symbols, {len(modules)} modules')

    self_all, self_busy, incl_busy, waiters, focus = (collections.Counter() for _ in range(5))
    busy = waits = 0
    for sample in samples:
        leaf = name(sample[0])
        frames = [name(a) for a in sample[1:] if a]
        if is_wait(leaf, bool(modules)):
            waits += 1
            emu = [f for f in frames if f.startswith('kyty!')][:2]
            waiters[('  <-  '.join(f[5:] for f in emu)) or leaf] += 1
        else:
            busy += 1
            self_busy[leaf] += 1
            for f in {leaf, *frames}:
                if f != '?':
                    incl_busy[f] += 1
        self_all[leaf] += 1
        if args.focus and args.focus in leaf:
            emu = [f for f in frames if f.startswith('kyty!')][:2]
            focus[('  <-  '.join(f[5:] for f in emu)) or '?'] += 1

    print(f'busy {busy} ({100.0 * busy / max(count, 1):.1f}%), waiting {waits} ({100.0 * waits / max(count, 1):.1f}%)')
    table('self, all samples', self_all, count, args.top)
    table('self, busy samples', self_busy, busy, args.top)
    table('inclusive, busy samples', incl_busy, busy, args.top)
    table('waiting samples by emulator caller', waiters, waits, 25)
    if args.focus:
        table(f'callers of leaves containing "{args.focus}"', focus, sum(focus.values()), 25)


if __name__ == '__main__':
    main()
