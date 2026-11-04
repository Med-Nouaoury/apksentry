import random, sys, struct
from unicorn import *
from unicorn.arm64_const import *
from capstone import *

N = int(sys.argv[1]); seed = int(sys.argv[2]); out = open(sys.argv[3], 'w')
rnd = random.Random(seed)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
CODE = 0x10000
DLO, DHI = 0xF8000, 0x118000
fill = bytes(((i * 2654435761) >> 13) & 0xff for i in range(DHI - DLO))
SKIP = ('svc', 'brk', 'hvc', 'smc', 'eret', 'hlt', 'dcps', 'drps', 'pac', 'aut', 'xpac', 'retaa', 'retab', 'eretaa', 'eretab', 'braa', 'brab', 'blraa', 'blrab', 'ldraa', 'ldrab', 'wfe', 'wfi', 'sev', 'yield', 'isb', 'clrex', 'sys', 'tlbi', 'at ', 'msr', 'mrs', 'dc ', 'ic ')
CLASSES = [0b1000, 0b1001, 0b1010, 0b1011, 0b0100, 0b0110, 0b1100, 0b1110, 0b0101, 0b1101, 0b0111, 0b1111]
XR = [UC_ARM64_REG_X0 + i for i in range(29)] + [UC_ARM64_REG_X29, UC_ARM64_REG_X30]
VR = [UC_ARM64_REG_Q0 + i for i in range(32)]

def rval(mem):
    if mem: return 0x104000 + rnd.randrange(0, 0x8000) & ~0xf
    k = rnd.random()
    if k < 0.3: return rnd.getrandbits(64)
    if k < 0.5: return rnd.getrandbits(32)
    if k < 0.7: return rnd.randrange(0, 256)
    if k < 0.8: return (1 << 64) - rnd.randrange(1, 300)
    return rnd.choice([0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0x7fffffffffffffff, 0x8000000000000000, (1 << 64) - 1])

made = 0; tries = 0
while made < N:
    tries += 1
    w = rnd.getrandbits(32)
    w = (w & ~(0xf << 25)) | (rnd.choice(CLASSES) << 25)
    dis = list(md.disasm(struct.pack('<I', w), CODE))
    if not dis: continue
    txt = (dis[0].mnemonic + ' ' + dis[0].op_str).lower()
    if txt.startswith(SKIP): continue
    mem = rnd.random() < 0.5
    xs = [rval(mem) for _ in range(31)]
    sp = 0x108000 + rnd.randrange(0, 0x4000) & ~0xf
    nzcv = rnd.randrange(16)
    vs = [rnd.getrandbits(128) if rnd.random() < 0.7 else rnd.choice([0, (1 << 128) - 1, 0x3ff0000000000000, 0x7ff8000000000000]) for _ in range(32)]
    tp = rnd.getrandbits(64)
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(CODE, 0x1000); uc.mem_write(CODE, struct.pack('<I', w))
    uc.mem_map(DLO, DHI - DLO); uc.mem_write(DLO, fill)
    uc.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)
    for r, v in zip(XR, xs): uc.reg_write(r, v)
    uc.reg_write(UC_ARM64_REG_SP, sp); uc.reg_write(UC_ARM64_REG_NZCV, nzcv << 28)
    for r, v in zip(VR, vs): uc.reg_write(r, v)
    uc.reg_write(UC_ARM64_REG_TPIDR_EL0, tp)
    writes = []
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, a, addr, size, val, ud: writes.append((addr, size)))
    status = 'ok'
    try:
        uc.emu_start(CODE, CODE + 4, count=1)
    except UcError as e:
        if e.errno == UC_ERR_FETCH_UNMAPPED:
            status = 'ok'  # تفرّع إلى عنوان غير محجوز: التعليمة نفسها نُفّذت
        elif e.errno in (UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED, UC_ERR_READ_UNALIGNED, UC_ERR_WRITE_UNALIGNED):
            status = 'fault'
        else:
            continue  # تعليمة غير صالحة عند Unicorn: نتجاهلها
    pc = uc.reg_read(UC_ARM64_REG_PC)
    if status == 'ok' and pc == CODE:  # استثناء صامت
        continue
    line = ['%08x' % w, '1' if mem else '0', '%x' % sp, '%x' % nzcv, '%x' % tp] + ['%x' % v for v in xs] + ['%x' % v for v in vs]
    line.append(status)
    if status == 'ok':
        ys = [uc.reg_read(r) for r in XR]
        line += ['%x' % uc.reg_read(UC_ARM64_REG_SP), '%x' % pc, '%x' % (uc.reg_read(UC_ARM64_REG_NZCV) >> 28)] + ['%x' % v for v in ys] + ['%x' % uc.reg_read(r) for r in VR]
        wl = []
        for a, s in writes:
            if DLO <= a < DHI: wl.append('%x:%s' % (a, uc.mem_read(a, s).hex()))
        line.append(','.join(wl) if wl else '-')
    line.append(txt.replace(' ', '_'))
    out.write(' '.join(line) + '\n'); made += 1
print('cases', made, 'tries', tries)
