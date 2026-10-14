"""Small QR code encoder: byte mode, error correction level M, versions 1 to 10 (up to 213 bytes).
Enough for an otpauth:// link. Returns the modules as a list of strings of '0' and '1'."""

# version: (ec codewords per block, [(blocks, data codewords per block), ...]) for level M
_M = {1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]), 5: (24, [(2, 43)]),
      6: (16, [(4, 27)]), 7: (18, [(4, 31)]), 8: (22, [(2, 38), (2, 39)]), 9: (22, [(3, 36), (2, 37)]),
      10: (26, [(4, 43), (1, 44)])}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42],
          9: [6, 26, 46], 10: [6, 28, 50]}

_EXP, _LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x; _LOG[_x] = _i
    _x <<= 1
    if _x & 256:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gmul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rs(data, n):
    gen = [1]
    for i in range(n):
        nxt = [0] * (len(gen) + 1)
        for j, g in enumerate(gen):
            nxt[j] ^= g
            nxt[j + 1] ^= _gmul(g, _EXP[i])
        gen = nxt
    rem = [0] * n
    for b in data:
        f = b ^ rem[0]
        rem = rem[1:] + [0]
        if f:
            for j in range(n):
                rem[j] ^= _gmul(gen[j + 1], f)
    return rem


def _bits(data, version):
    bits = "0100" + format(len(data), "08b" if version < 10 else "016b") + "".join(format(b, "08b") for b in data)
    cap = sum(n * d for n, d in _M[version][1]) * 8
    bits += "0" * min(4, cap - len(bits))
    bits += "0" * (-len(bits) % 8)
    out = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]
    n0, pad = len(out), (0xEC, 0x11)
    while len(out) < cap // 8:
        out.append(pad[(len(out) - n0) % 2])
    return out


def _codewords(data, version):
    ec, groups = _M[version]
    words = _bits(data, version)
    blocks, pos = [], 0
    for n, d in groups:
        for _ in range(n):
            blocks.append(words[pos:pos + d]); pos += d
    ecs = [_rs(b, ec) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec):
        for e in ecs:
            out.append(e[i])
    return "".join(format(c, "08b") for c in out)


def _format_bits(mask):
    data = (0b00 << 3) | mask  # level M = 00
    rem = data << 10
    for i in range(14, 9, -1):
        if rem >> i & 1:
            rem ^= 0x537 << (i - 10)
    return ((data << 10) | rem) ^ 0x5412


def _version_bits(version):
    rem = version << 12
    for i in range(17, 11, -1):
        if rem >> i & 1:
            rem ^= 0x1F25 << (i - 12)
    return (version << 12) | rem


_MASKS = [lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0,
          lambda r, c: (r + c) % 3 == 0, lambda r, c: (r // 2 + c // 3) % 2 == 0,
          lambda r, c: (r * c) % 2 + (r * c) % 3 == 0, lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
          lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0]


def _penalty(m):
    n = len(m)
    p = 0
    for grid in (m, [list(col) for col in zip(*m)]):
        for row in grid:
            run = 1
            for i in range(1, n):
                if row[i] == row[i - 1]:
                    run += 1
                else:
                    if run >= 5: p += run - 2
                    run = 1
            if run >= 5: p += run - 2
            s = "".join("1" if v else "0" for v in row)
            p += 40 * (s.count("10111010000") + s.count("00001011101"))
    for r in range(n - 1):
        for c in range(n - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                p += 3
    dark = sum(sum(1 for v in row if v) for row in m)
    p += 10 * (abs(dark * 100 // (n * n) - 50) // 5)
    return p


def encode(text):
    data = text.encode("utf-8")
    version = next((v for v in _M if len(data) <= sum(n * d for n, d in _M[v][1]) - (3 if v < 10 else 4)), None)
    if version is None:
        raise ValueError("text too long for the QR code")
    size = 17 + 4 * version
    base = [[None] * size for _ in range(size)]  # None = data module, else fixed

    def put(r, c, v):
        if 0 <= r < size and 0 <= c < size:
            base[r][c] = v

    def finder(r0, c0):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                inside = 0 <= dr <= 6 and 0 <= dc <= 6
                v = inside and (dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4))
                put(r0 + dr, c0 + dc, bool(v))
    finder(0, 0); finder(0, size - 7); finder(size - 7, 0)
    pos = _ALIGN[version]
    for r in pos:
        for c in pos:
            if (r, c) in ((6, 6), (6, pos[-1]), (pos[-1], 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    put(r + dr, c + dc, max(abs(dr), abs(dc)) != 1)
    for i in range(8, size - 8):
        put(6, i, i % 2 == 0); put(i, 6, i % 2 == 0)
    put(size - 8, 8, True)
    reserved = [[base[r][c] is not None for c in range(size)] for r in range(size)]
    for i in range(9):
        for (r, c) in ((8, i), (i, 8)):
            reserved[r][c] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True; reserved[size - 1 - i][8] = True
    if version >= 7:
        for i in range(6):
            for j in range(3):
                reserved[i][size - 11 + j] = True; reserved[size - 11 + j][i] = True
    bits = _codewords(data, version)
    # place data (zig-zag from bottom right, skipping column 6)
    cells, idx, up = [], 0, True
    c = size - 1
    while c > 0:
        if c == 6:
            c -= 1
        rows = range(size - 1, -1, -1) if up else range(size)
        for r in rows:
            for cc in (c, c - 1):
                if not reserved[r][cc]:
                    cells.append((r, cc))
        up = not up
        c -= 2
    best = None
    for mask in range(8):
        m = [[bool(v) if v is not None else False for v in row] for row in base]
        for i, (r, cc) in enumerate(cells):
            bit = bits[i] == "1" if i < len(bits) else False
            m[r][cc] = bit != _MASKS[mask](r, cc)
        f = _format_bits(mask)
        for i in range(15):
            bit = bool(f >> i & 1)
            # copy 1 around the top-left finder
            if i < 6: m[i][8] = bit
            elif i < 8: m[i + 1][8] = bit
            elif i == 8: m[8][7] = bit
            else: m[8][14 - i] = bit
            # copy 2 split between the other two finders
            if i < 8: m[8][size - 1 - i] = bit
            else: m[size - 15 + i][8] = bit
        if version >= 7:
            vb = _version_bits(version)
            for i in range(18):
                bit = bool(vb >> i & 1)
                m[i // 3][size - 11 + i % 3] = bit
                m[size - 11 + i % 3][i // 3] = bit
        pen = _penalty(m)
        if best is None or pen < best[0]:
            best = (pen, m)
    return ["".join("1" if v else "0" for v in row) for row in best[1]]
