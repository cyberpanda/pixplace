# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CyberPanda (github.com/cyberpanda)

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]

def _mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]

def _rs_generator(n):
    g = [1]
    for i in range(n):
        ng = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            ng[j] ^= c
            ng[j + 1] ^= _mul(c, _EXP[i])
        g = ng
    return g

def _rs_encode(data, n):
    gen = _rs_generator(n)
    res = [0] * n
    for b in data:
        f = b ^ res[0]
        res = res[1:] + [0]
        for i, gc in enumerate(gen[1:]):
            res[i] ^= _mul(gc, f)
    return res

_VER = {
    1:  (10, 1, 16,  0, 0),
    2:  (16, 1, 28,  0, 0),
    3:  (26, 1, 44,  0, 0),
    4:  (18, 2, 32,  0, 0),
    5:  (24, 2, 43,  0, 0),
    6:  (16, 4, 27,  0, 0),
    7:  (18, 4, 31,  0, 0),
    8:  (22, 2, 38,  2, 39),
    9:  (22, 3, 36,  2, 37),
    10: (26, 4, 43,  1, 44),
}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
          7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}

def _capacity(v):
    ecc, b1, d1, b2, d2 = _VER[v]
    return b1 * d1 + b2 * d2

def _choose_version(n_bytes):
    for v in sorted(_VER):

        lenbits = 8 if v < 10 else 16
        need = (4 + lenbits + n_bytes * 8 + 7) // 8
        if need <= _capacity(v):
            return v
    raise ValueError("Text zu lang fuer diesen QR-Erzeuger")

def _bitstream(data, version):
    lenbits = 8 if version < 10 else 16
    bits = []

    def put(val, n):
        for i in range(n - 1, -1, -1):
            bits.append((val >> i) & 1)

    put(0b0100, 4)
    put(len(data), lenbits)
    for b in data:
        put(b, 8)
    cap = _capacity(version) * 8
    put(0, min(4, cap - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    pad = [0xEC, 0x11]
    i = 0
    while len(bits) < cap:
        put(pad[i % 2], 8)
        i += 1
    return bits

def _codewords(data, version):
    bits = _bitstream(data, version)
    allb = [int("".join(map(str, bits[i:i + 8])), 2)
            for i in range(0, len(bits), 8)]
    ecc_n, b1, d1, b2, d2 = _VER[version]
    blocks, eccs, pos = [], [], 0
    for _ in range(b1):
        blocks.append(allb[pos:pos + d1]); pos += d1
    for _ in range(b2):
        blocks.append(allb[pos:pos + d2]); pos += d2
    for blk in blocks:
        eccs.append(_rs_encode(blk, ecc_n))
    out = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ecc_n):
        for e in eccs:
            out.append(e[i])
    return out

def _new_matrix(size):
    return [[None] * size for _ in range(size)]

def _place_static(m, version):
    size = len(m)

    def finder(r, c):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                rr, cc = r + dr, c + dc
                if not (0 <= rr < size and 0 <= cc < size):
                    continue
                inring = (dr in (0, 6) and 0 <= dc <= 6) or \
                         (dc in (0, 6) and 0 <= dr <= 6)
                incore = 2 <= dr <= 4 and 2 <= dc <= 4
                m[rr][cc] = 1 if (inring or incore) else 0

    finder(0, 0); finder(0, size - 7); finder(size - 7, 0)
    for i in range(size):
        if m[6][i] is None:
            m[6][i] = 1 if i % 2 == 0 else 0
        if m[i][6] is None:
            m[i][6] = 1 if i % 2 == 0 else 0

    coords = _ALIGN[version]
    skip = {(6, 6), (6, size - 7), (size - 7, 6)}
    for r in coords:
        for c in coords:
            if (r, c) in skip:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    m[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0
    if version >= 7:
        for i in range(18):
            r, c = i // 3, size - 11 + i % 3
            m[r][c] = 0
            m[c][r] = 0
    m[size - 8][8] = 1
    for i in range(9):
        if m[8][i] is None:
            m[8][i] = 0
        if m[i][8] is None:
            m[i][8] = 0
    for i in range(8):
        if m[8][size - 1 - i] is None:
            m[8][size - 1 - i] = 0
        if m[size - 1 - i][8] is None:
            m[size - 1 - i][8] = 0

def _mask(i, r, c):
    return [lambda: (r + c) % 2 == 0,
            lambda: r % 2 == 0,
            lambda: c % 3 == 0,
            lambda: (r + c) % 3 == 0,
            lambda: (r // 2 + c // 3) % 2 == 0,
            lambda: (r * c) % 2 + (r * c) % 3 == 0,
            lambda: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
            lambda: ((r + c) % 2 + (r * c) % 3) % 2 == 0][i]()

def _penalty(m):
    size = len(m)
    p = 0
    for line in list(m) + [list(col) for col in zip(*m)]:
        run, prev = 1, line[0]
        for v in line[1:]:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    p += 3 + (run - 5)
                run, prev = 1, v
        if run >= 5:
            p += 3 + (run - 5)
    for r in range(size - 1):
        for c in range(size - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                p += 3

    seq_a = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    seq_b = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
    for line in list(m) + [list(col) for col in zip(*m)]:
        for i in range(len(line) - 10):
            win = line[i:i + 11]
            if win == seq_a or win == seq_b:
                p += 40
    dark = sum(sum(r) for r in m)
    p += 10 * (abs(dark * 100 // (size * size) - 50) // 5)
    return p

_FMT_M = {0: 0x5412, 1: 0x5125, 2: 0x5E7C, 3: 0x5B4B,
          4: 0x45F9, 5: 0x40CE, 6: 0x4F97, 7: 0x4AA0}

_VERINFO = {7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3}

def _put_version(m, version):
    if version < 7:
        return
    size = len(m)
    bits = _VERINFO[version]
    for i in range(18):
        b = (bits >> i) & 1
        r, c = i // 3, size - 11 + i % 3
        m[r][c] = b
        m[c][r] = b

def _put_format(m, mask):
    size = len(m)
    bits = _FMT_M[mask]
    for i in range(15):
        b = (bits >> (14 - i)) & 1
        if i < 6:
            m[8][i] = b
        elif i == 6:
            m[8][7] = b
        elif i == 7:
            m[8][8] = b
        elif i == 8:
            m[7][8] = b
        else:
            m[14 - i][8] = b
        if i < 8:
            m[size - 1 - i][8] = b
        else:
            m[8][size - 15 + i] = b

def qr_matrix(text: str):
    data = text.encode("utf-8")
    version = _choose_version(len(data))
    size = version * 4 + 17
    words = _codewords(data, version)

    base = _new_matrix(size)
    _place_static(base, version)
    reserved = [[base[r][c] is not None for c in range(size)]
                for r in range(size)]

    bits = []
    for w in words:
        for i in range(7, -1, -1):
            bits.append((w >> i) & 1)

    best = None
    for mask in range(8):
        m = [row[:] for row in base]
        idx, upward, col = 0, True, size - 1
        while col > 0:
            if col == 6:
                col -= 1
            rows = range(size - 1, -1, -1) if upward else range(size)
            for r in rows:
                for c in (col, col - 1):
                    if reserved[r][c]:
                        continue
                    b = bits[idx] if idx < len(bits) else 0
                    idx += 1
                    if _mask(mask, r, c):
                        b ^= 1
                    m[r][c] = b
            upward = not upward
            col -= 2
        _put_format(m, mask)
        _put_version(m, version)
        m = [[0 if v is None else v for v in row] for row in m]
        pen = _penalty(m)
        if best is None or pen < best[0]:
            best = (pen, m)
    return best[1]

def qr_svg(text: str, quiet: int = 4, scale: int = 4) -> str:
    m = qr_matrix(text)
    n = len(m)
    total = (n + quiet * 2) * scale
    parts = []
    for r in range(n):
        for c in range(n):
            if m[r][c]:
                parts.append('<rect x="%d" y="%d" width="%d" height="%d"/>'
                             % ((c + quiet) * scale, (r + quiet) * scale,
                                scale, scale))
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
            'viewBox="0 0 %d %d" shape-rendering="crispEdges">'
            '<rect width="%d" height="%d" fill="#fff"/>'
            '<g fill="#000">%s</g></svg>'
            % (total, total, total, total, total, total, "".join(parts)))
