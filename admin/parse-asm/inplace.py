# Checks the generated s2n-bignum kernels that rind runs in place, which their
# proofs exclude.
#
# A kernel runs in place when its generated `asm!` binds one Rust pointer to
# two registers, and might when it takes a raw pointer, which callers may
# alias. Every such kernel is walked, instruction by instruction, for every
# buffer length up to MAX blocks, checking that:
#
# - every byte of the buffer is loaded before it is stored, and every byte is
#   loaded and stored, inside the buffer;
# - each of the two registers only loads or only stores, and is never copied
#   anywhere the walk cannot follow, so no output is read back;
# - every branch resolves from the length alone, and every address is an
#   argument pointer plus constants, so the control flow and addressing are
#   constant time;
# - every instruction reachable from the entry is walked.
#
# Registers hold known integers, or pointers: an argument plus a byte offset.
# Anything loaded from memory, or computed by an instruction the walk does not
# model, is unknown. A kernel the walk cannot follow fails.
#
# Before that, it plants faults in each kernel and checks that the walk
# catches every one, so a walk that stops checking fails too.
#
# Run from this directory: python3 inplace.py
import glob
import re
import sys

MAX = 64
GENERATED = "../../rind/src/low/*/*.rs"
HEADER = "// generated source. do not edit.\n"

INSN = re.compile(
    r'\s*Q!\("    (\S+)\s*"(?: "([^"]*)")?(?: Label!\("\w+", (\d+), (Before|After)\))?\),$'
)
LABEL = re.compile(r'\s*Q!\(Label!\("\w+", (\d+)\) ":"\),$')
BINDING = re.compile(
    r'\s*(in|out|lateout|inout|inlateout)\("(\w+)"\) (.+?)(?: => (.+))?,$'
)
DECL = re.compile(
    r"^pub\(crate\) (?:unsafe )?fn \w+\((.*?)\)(?: -> [^{]*)? \{$", re.S | re.M
)
GPR = re.compile(r"^(?:[xw](\d+)|xzr|wzr|sp)$")
# Instructions that leave the flags alone. Any other clears what the walk
# knows of them, so a flag writer it has never seen cannot hide behind a
# compare of the length.
KEEPS_FLAGS = {"add", "sub", "mov", "movi", "movk", "and", "orr", "eor", "eor3"}
KEEPS_FLAGS |= {"lsr", "shl", "ext", "rev", "rev32", "rev64", "trn1", "trn2"}
KEEPS_FLAGS |= {"tbl", "fmov", "aese", "aesmc", "pmull", "pmull2"}
MEMORY = {"ldr", "ldp", "ldur", "ld1", "str", "stp", "stur", "st1"}
SIZES = {"q": 16, "x": 8, "d": 8, "w": 4, "s": 4, "h": 2, "b": 1}
CONDITIONS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "lt": lambda a, b: a < b,
    "ge": lambda a, b: a >= b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
}


class Fault(Exception):
    # `kind` names the property that failed, so the self-test can tell that a
    # planted fault was caught by the check meant to catch it.
    def __init__(self, kind, detail):
        super().__init__("%s: %s" % (kind, detail))
        self.kind = kind


class Unmodelled(Exception):
    pass


def split_ops(args):
    # Split on commas outside [] and {}.
    out, depth, cur = [], 0, ""
    for c in args:
        if c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def reg(tok):
    m = GPR.match(tok)
    if not m:
        return None
    if tok in ("xzr", "wzr"):
        return "zr"
    if tok == "sp":
        return "sp"
    return "x" + m.group(1)


def imm(tok):
    if not tok.startswith("#"):
        raise Unmodelled
    return int(tok[1:], 0)


def width(v, bits):
    # A 32-bit result zero-extends; a pointer never fits one.
    if bits == 64:
        return v
    if not isinstance(v, int):
        raise Unmodelled
    return v & 0xFFFFFFFF


def signed(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class Kernel:
    def __init__(self, path, text):
        self.path = path
        lines = text.split("\n")
        if (
            lines.count("        core::arch::asm!(") != 1
            or "            )" not in lines
        ):
            raise Fault("parse", "%s: not one asm! block" % path)
        start = lines.index("        core::arch::asm!(") + 1
        self.body = lines[start : lines.index("            )", start)]
        self.bindings = {}  # register -> Rust expression
        for line in self.body:
            m = BINDING.match(line)
            if m and m.group(1) in ("in", "inout", "inlateout"):
                self.bindings[m.group(2)] = m.group(3)
        m = DECL.search(text)
        if not self.bindings or not m:
            raise Fault("parse", "%s: no arguments found" % path)
        self.params = {}
        for p in split_ops(m.group(1)):
            name, _, ty = p.partition(":")
            self.params[name.strip()] = ty.strip()
        self._insns = self._layout = None

    @property
    def insns(self):
        # (op, args, target index or None), parsed only for kernels walked:
        # other kernels' templates use macros this does not expand.
        if self._insns is None:
            self._insns = self.parse()
        return self._insns

    def parse(self):
        insns = []
        labels = []  # (index, id)
        refs = []  # (instruction index, id, direction)
        for line in self.body:
            if not line.strip() or line.strip().startswith("//") or BINDING.match(line):
                continue
            m = LABEL.match(line)
            if m:
                labels.append((len(insns), m.group(1)))
                continue
            m = INSN.match(line)
            if not m:
                raise Fault("parse", "%s: unrecognised line %r" % (self.path, line))
            if m.group(3):
                refs.append((len(insns), m.group(3), m.group(4)))
            insns.append((m.group(1), m.group(2) or "", None))
        # Local labels resolve as the assembler does: by id, to the nearest
        # definition before (`Before`) or after (`After`) the branch.
        for at, id, direction in refs:
            if direction == "Before":
                found = [i for i, l in labels if l == id and i <= at]
                target = found[-1] if found else None
            else:
                found = [i for i, l in labels if l == id and i > at]
                target = found[0] if found else None
            if target is None:
                raise Fault("parse", "%s: unresolved label %s" % (self.path, id))
            op, args, _ = insns[at]
            insns[at] = (op, args, target)
        return insns

    def in_place(self):
        # Rust references never alias, so only one pointer bound to several
        # registers, or a raw pointer, can make a kernel run in place.
        roots = {}
        for r, expr in self.bindings.items():
            m = re.fullmatch(r"(\w+)\.as_(?:mut_)?ptr\(\)", expr)
            root = m.group(1) if m else expr if self.raw(expr) else None
            if root:
                roots.setdefault(root, []).append(r)
        return any(len(r) > 1 for r in roots.values()) or any(
            map(self.raw, self.params)
        )

    def raw(self, param):
        return self.params.get(param, "").startswith("*")

    def layout(self):
        if self._layout is None:
            self._layout = self.find_layout()
        return self._layout

    def find_layout(self):
        # The one shape walked so far: a raw pointer to fixed-size blocks,
        # bound to two registers, and a block count, bound as a multiple.
        if "/aarch64/" not in self.path:
            raise Fault("signature", "%s: the walk models only aarch64" % self.path)
        raws = [p for p in self.params if self.raw(p)]
        counts = [p for p, ty in self.params.items() if ty == "usize"]
        if len(raws) != 1 or len(counts) != 1:
            raise Fault(
                "signature",
                "%s: needs one raw pointer and one usize, has %s"
                % (self.path, self.params),
            )
        buf, count = raws[0], counts[0]
        m = re.fullmatch(r"\*(?:mut|const) \[u8; (\d+)\]", self.params[buf])
        if not m:
            raise Fault(
                "signature", "%s: unmodelled buffer %s" % (self.path, self.params[buf])
            )
        # Each other register: (argument, 0) for a pointer, or (None, scale).
        regs, homes, scale = {}, [], None
        for r, expr in sorted(self.bindings.items()):
            if expr == buf:
                homes.append(r)
                continue
            m2 = re.fullmatch(r"%s(?: \* (\d+))?" % count, expr)
            if m2:
                scale = int(m2.group(1) or 1)
                regs[r] = (None, scale)
                continue
            m2 = re.fullmatch(r"(\w+)\.as_(?:mut_)?ptr\(\)", expr)
            if m2 and self.params.get(m2.group(1), "").startswith("&"):
                regs[r] = (m2.group(1), 0)
                continue
            raise Fault(
                "signature", "%s: unmodelled argument %s = %s" % (self.path, r, expr)
            )
        if len(homes) != 2 or scale is None:
            raise Fault(
                "signature",
                "%s: needs %s in two registers and %s in one" % (self.path, buf, count),
            )
        return int(m.group(1)), homes, regs

    def reachable(self):
        # Instructions the entry reaches through any branch edge. Not every
        # edge: a guard against lengths rind never passes is never taken.
        seen, todo = set(), [0]
        while todo:
            pc = todo.pop()
            if pc in seen or pc >= len(self.insns):
                continue
            seen.add(pc)
            op, _, target = self.insns[pc]
            if target is not None:
                todo.append(target)
            if op not in ("b", "br", "ret"):
                todo.append(pc + 1)
        return seen


class Walk:
    def __init__(self, kernel, blocks):
        self.insns = kernel.insns
        size, self.homes, regs = kernel.layout()
        self.size = size * blocks
        self.r = {"zr": 0, "sp": ("sp", 0)}
        for r, (arg, scale) in regs.items():
            self.r[r] = blocks * scale if arg is None else (arg, 0)
        for r in self.homes:
            self.r[r] = (r, 0)
        self.role = {}
        self.flags = None
        self.events = []
        self.walked = set()

    def get(self, name):
        if name not in self.r:
            raise Unmodelled
        return self.r[name]

    def set(self, name, v):
        if name == "zr":
            return
        if v is None:
            self.r.pop(name, None)
        else:
            if isinstance(v, int):
                v &= (1 << 64) - 1
            self.r[name] = v

    def is_buf(self, name):
        v = self.r.get(name)
        return isinstance(v, tuple) and v[0] in self.homes

    def operand(self, tok):
        if tok.startswith("#"):
            return imm(tok)
        r = reg(tok)
        if r is None:
            raise Unmodelled
        # A w register reads the low half; a pointer has none.
        return width(self.get(r), 32 if tok[0] == "w" else 64)

    def shifted(self, ops):
        # The second source of add/sub/cmp, with an optional shift.
        v = self.operand(ops[0])
        if len(ops) == 1:
            return v
        kind, amount = ops[1].split()
        if not isinstance(v, int) or kind not in ("lsl", "lsr"):
            raise Unmodelled
        return v << imm(amount) if kind == "lsl" else v >> imm(amount)

    def add(self, a, b, sign):
        if isinstance(a, tuple) and isinstance(b, int):
            return (a[0], a[1] + sign * b)
        if isinstance(a, int) and isinstance(b, tuple) and sign == 1:
            return (b[0], b[1] + a)
        if (
            isinstance(a, tuple)
            and isinstance(b, tuple)
            and sign == -1
            and a[0] == b[0]
        ):
            return a[1] - b[1]
        if isinstance(a, int) and isinstance(b, int):
            return a + sign * b
        raise Unmodelled

    def compare(self, a, b, bits):
        # Pointers compare only against the same argument; anything else
        # leaves the flags unknown, so a branch on them fails.
        if isinstance(a, tuple) or isinstance(b, tuple):
            if not (isinstance(a, tuple) and isinstance(b, tuple) and a[0] == b[0]):
                return None
            a, b = a[1], b[1]
        return ("cmp", signed(a, bits), signed(b, bits))

    def cond(self, pc, c):
        if self.flags is None:
            raise Fault("branch", "%s on flags not from the length" % (self.insns[pc],))
        kind, a, b = self.flags
        if c not in CONDITIONS or (kind == "tst" and c not in ("eq", "ne")):
            raise Fault("unmodelled", "condition %s after %s" % (c, kind))
        return CONDITIONS[c](a, b)

    def mem(self, pc, op, ops):
        where = self.insns[pc]
        addr = ops[-1]
        post = None
        if addr.startswith("#"):
            post = imm(addr)
            ops, addr = ops[:-1], ops[-2]
        m = re.match(r"^\[(\w+)(?:, #(-?\w+))?\]\s*(!?)$", addr)
        if not m or reg(m.group(1)) is None:
            raise Fault("unmodelled", "addressing mode %s" % (where,))
        base, off, pre = reg(m.group(1)), int(m.group(2) or "0", 0), m.group(3)
        data = ops[:-1]
        load = op.startswith("ld")
        dregs = [reg(d) for d in data if reg(d)]
        vregs = [d for d in data if not reg(d)]
        if not load:
            for d in dregs:
                if self.is_buf(d):
                    raise Fault("escape", "buffer pointer stored by %s" % (where,))
        v = self.r.get(base)
        if not isinstance(v, tuple):
            raise Fault("address", "address not from an argument in %s" % (where,))
        kind, at = v
        if kind in self.homes:
            if base != kind:
                raise Fault(
                    "escape", "access through a copied pointer in %s" % (where,)
                )
            role = "load" if load else "store"
            if self.role.setdefault(base, role) != role:
                raise Fault(
                    "direction", "%s both loads and stores, at %s" % (base, where)
                )
            addr = at + (0 if post is not None else off)
            # Scalar registers, or a list of whole 16-byte vector registers.
            if vregs and vregs[0].startswith("{"):
                lanes = split_ops(vregs[0].strip("{} "))
                if not all(v.endswith(".16b") for v in lanes):
                    raise Fault("unmodelled", "vector arrangement in %s" % (where,))
                size = 16 * len(lanes)
            elif all(d[0] in SIZES for d in data):
                size = sum(SIZES[d[0]] for d in data)
            else:
                raise Fault("unmodelled", "data registers in %s" % (where,))
            self.events.append((load, addr, size, where))
        if pre or post is not None:
            self.set(base, (kind, at + (off if pre else post)))
        if load:
            for d in dregs:
                self.set(d, None)

    def step(self, pc):
        op, args, target = self.insns[pc]
        ops = split_ops(args)
        nxt = pc + 1
        if op in MEMORY:
            self.mem(pc, op, ops)
            return nxt
        if op[:2] in ("ld", "st"):
            raise Fault("unmodelled", "memory access %s" % (self.insns[pc],))
        if op == "b":
            return target
        if op.startswith("b."):
            return target if self.cond(pc, op[2:]) else nxt
        if op in ("cbz", "cbnz"):
            try:
                v = self.operand(ops[0])
            except Unmodelled:
                v = None
            if not isinstance(v, int):
                raise Fault(
                    "branch", "%s on a value not from the length" % (self.insns[pc],)
                )
            return target if (v == 0) == (op == "cbz") else nxt
        if target is not None or op in ("br", "blr", "bl", "ret"):
            raise Fault("unmodelled", "control flow %s" % (self.insns[pc],))
        if op not in KEEPS_FLAGS:
            self.flags = None
        if re.search(r"\[(?:[xw]\d+|sp)\b", args):
            raise Fault("unmodelled", "memory operand in %s" % (self.insns[pc],))
        regs = [reg(o.split()[0]) for o in ops]
        d = regs[0] if regs else None
        bits = 32 if ops and ops[0].startswith("w") else 64
        try:
            if op == "cmp":
                self.flags = self.compare(
                    self.operand(ops[0]), self.shifted(ops[1:]), bits
                )
            elif op == "tst":
                a, b = self.operand(ops[0]), self.operand(ops[1])
                if not (isinstance(a, int) and isinstance(b, int)):
                    raise Unmodelled
                self.flags = ("tst", a & b, 0)
            elif op == "subs" and d:
                a, b = self.operand(ops[1]), self.shifted(ops[2:])
                self.flags = self.compare(a, b, bits)
                self.set(d, width(self.add(a, b, -1), bits))
            elif op in ("add", "sub") and d and len(ops) >= 3:
                v = self.add(
                    self.operand(ops[1]),
                    self.shifted(ops[2:]),
                    1 if op == "add" else -1,
                )
                self.set(d, width(v, bits))
            elif op == "mov" and d and len(ops) == 2:
                self.set(d, width(self.operand(ops[1]), bits))
            elif op in ("and", "lsr", "lsl") and d and len(ops) == 3:
                a, b = self.operand(ops[1]), self.operand(ops[2])
                if not (isinstance(a, int) and isinstance(b, int)):
                    raise Unmodelled
                shift = b & (bits - 1)
                v = {"and": a & b, "lsr": a >> shift, "lsl": a << shift}[op]
                self.set(d, width(v, bits))
            else:
                raise Unmodelled
        except Unmodelled:
            # No buffer pointer may flow in, and a register written becomes
            # unknown.
            for s in regs[1:] if d else regs:
                if s and self.is_buf(s):
                    raise Fault(
                        "escape", "buffer pointer escapes into %s" % (self.insns[pc],)
                    )
            if d and op not in ("cmp", "cmn", "tst", "ccmp", "ccmn"):
                self.set(d, None)
        return nxt

    def run(self):
        pc, steps = 0, 0
        while pc < len(self.insns):
            steps += 1
            if steps > 10**6:
                raise Fault("unmodelled", "no exit after %d steps" % steps)
            nxt = self.step(pc)
            self.walked.add(pc)
            pc = nxt


def check(kernel):
    walked = set()
    for n in range(MAX + 1):
        w = Walk(kernel, n)
        w.run()
        walked |= w.walked
        # Per byte: no load after its store, and every byte loaded and stored.
        loaded = [False] * w.size
        stored = [False] * w.size
        for load, addr, size, where in w.events:
            if addr < 0 or addr + size > w.size:
                raise Fault(
                    "bounds",
                    "n=%d: %s reaches [%d, %d) of %d bytes"
                    % (n, where, addr, addr + size, w.size),
                )
            for b in range(addr, addr + size):
                if load:
                    if stored[b]:
                        raise Fault(
                            "order",
                            "n=%d: byte %d loaded by %s after its store"
                            % (n, b, where),
                        )
                    loaded[b] = True
                else:
                    stored[b] = True
        if not (all(stored) and all(loaded)):
            raise Fault("coverage", "n=%d: a byte is never loaded or never stored" % n)
    missed = kernel.reachable() - walked
    if missed:
        raise Fault(
            "unreached",
            "%d reachable instructions never walked, first %s"
            % (len(missed), kernel.insns[min(missed)]),
        )
    return len(walked)


def planted(kernel, text):
    # Most faults go right before the kernel's first load from the buffer,
    # which runs before any store to it, when both pointers are at its start.
    _, homes, regs = kernel.layout()
    other = next(r for r, (arg, _) in sorted(regs.items()) if arg is not None)
    lines = text.split("\n")
    loads = [
        i
        for i, line in enumerate(lines)
        if re.search(r'"    ld\w+ .*\[(%s)\b' % "|".join(homes), line)
    ]
    if not loads:
        raise Fault(
            "self-test",
            "%s: no load from the buffer to plant faults before" % kernel.path,
        )
    first = loads[0]
    src = re.search(r"\[(\w+)", lines[first]).group(1)
    dst = next(h for h in homes if h != src)
    store = next(
        i
        for i, line in enumerate(lines)
        if re.search(r'"    st\w+ .*\[%s\b' % dst, line)
    )
    conds = [i for i, line in enumerate(lines) if re.search(r'"    b\.\w+ ', line)]
    step = re.search(r"#\w+(?=\]!|\"\),$)", lines[store])
    # A scratch register the kernel never touches, so the faults change
    # nothing else.
    used = set(re.findall(r"\b[xw](\d+)\b", "\n".join(kernel.body)))
    tmp = "x%d" % next(i for i in range(31) if str(i) not in used)

    def q(op, args="", target=None):
        args = ' "%s"' % args if args else ""
        if target:
            args += ' Label!("planted", %d, After)' % target
        return '        Q!("    %-16s"%s),' % (op, args)

    def insert(*new):
        return "\n".join(lines[:first] + list(new) + lines[first:])

    # Dropping the first store keeps any pointer step it made.
    dropped = [q("add", "%s, %s, %s" % (dst, dst, step.group(0)))] if step else []
    label = '        Q!(Label!("planted", 99) ":"),'
    # (the check that must catch it, the kernel with it planted)
    faults = [
        # A store to the first block before its load.
        ("order", insert(q("str", "q0, [%s]" % dst))),
        # A load before the buffer.
        ("bounds", insert(q("ldr", "q0, [%s, #-16]" % src))),
        # A store dropped.
        ("coverage", "\n".join(lines[:store] + dropped + lines[store + 1 :])),
        # A load through the output pointer.
        ("direction", insert(q("ldr", "q0, [%s]" % dst))),
        # A store through a copy of the input pointer.
        ("escape", insert(q("mov", "%s, %s" % (tmp, src)), q("str", "q0, [%s]" % tmp))),
        # An address loaded from memory.
        (
            "address",
            insert(q("ldr", "%s, [%s]" % (tmp, other)), q("ldr", "q0, [%s]" % tmp)),
        ),
        # A branch on loaded data.
        (
            "branch",
            insert(
                q("ldr", "%s, [%s]" % (tmp, other)), q("cbz", tmp + ", ", 99), label
            ),
        ),
        # A reachable instruction no length runs.
        (
            "unreached",
            insert(q("mov", tmp + ", #1"), q("cbnz", tmp + ", ", 99), q("ret"), label),
        ),
    ]
    if conds:
        # Flags set from a register the kernel never sets, before its first
        # conditional branch.
        msr = q("msr", "nzcv, " + tmp)
        faults.append(
            ("branch", "\n".join(lines[: conds[0]] + [msr] + lines[conds[0] :]))
        )
    return faults


def self_test(kernel, text):
    faults = planted(kernel, text)
    for kind, faulty in faults:
        try:
            check(Kernel(kernel.path, faulty))
        except Fault as f:
            if f.kind != kind:
                raise Fault(
                    "self-test",
                    "%s: planted %s fault caught as %s" % (kernel.path, kind, f),
                )
        else:
            raise Fault(
                "self-test", "%s: planted %s fault not caught" % (kernel.path, kind)
            )
    return len(faults)


def main():
    kernels = []
    for path in sorted(glob.glob(GENERATED)):
        text = open(path).read()
        if text.startswith(HEADER):
            kernel = Kernel(path, text)
            if kernel.in_place():
                kernels.append((kernel, text))
    if not kernels:
        raise Fault("self-test", "found no in-place kernel in %s" % GENERATED)
    for kernel, text in kernels:
        faults = self_test(kernel, text)
        walked = check(kernel)
        print(
            "ok %s: 0..=%d blocks in place, %d/%d instructions walked, %d planted faults caught"
            % (kernel.path, MAX, walked, len(kernel.insns), faults)
        )


if __name__ == "__main__":
    try:
        main()
    except Fault as f:
        print("error: %s" % f, file=sys.stderr)
        sys.exit(1)
