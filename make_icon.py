#!/usr/bin/env python3
"""VulnScanner 아이콘 생성 → icon.icns"""
import struct, zlib, os, subprocess, shutil

# ── PNG writer (pure stdlib) ─────────────────────────────────────────────────
def write_png(path, w, h, pixels):
    def chunk(name, data):
        c = name + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    raw = b''
    for row in pixels:
        raw += b'\x00'
        for r, g, b in row:
            raw += bytes([r, g, b])
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)))
        f.write(chunk(b'IDAT', zlib.compress(raw, 6)))
        f.write(chunk(b'IEND', b''))

# ── 색상 ──────────────────────────────────────────────────────────────────────
BG    = (11,  14,  17)    # #0b0e11
GOLD  = (240, 185, 11)    # #f0b90b
DARK  = (20,  23,  28)    # 방패 내부
WHITE = (234, 236, 239)   # #eaecef

# ── 방패 geometry ─────────────────────────────────────────────────────────────
SIZE = 512
cx   = SIZE // 2

def in_shield(x, y, shrink=0):
    nx  = x - cx
    top = int(SIZE * 0.10) + shrink
    mid = int(SIZE * 0.58) - shrink
    bot = int(SIZE * 0.91) - shrink
    if y < top or y > bot:
        return False
    hw = int(SIZE * 0.37) - shrink
    if hw <= 0:
        return False
    if y <= mid:
        return abs(nx) <= hw
    t    = (y - mid) / max(1, bot - mid)
    half = hw * (1.0 - t * 0.98)
    return half > 0 and abs(nx) <= half

# ── 체크마크 geometry ─────────────────────────────────────────────────────────
lw = SIZE * 0.038   # 선 두께

p1 = (int(cx * 0.55), int(SIZE * 0.635))
p2 = (int(cx * 0.86), int(SIZE * 0.800))
p3 = (int(cx * 1.52), int(SIZE * 0.450))

def dist_seg(px, py, x1, y1, x2, y2):
    dx, dy = x2 - x1, y2 - y1
    l2 = dx * dx + dy * dy
    if l2 == 0:
        return ((px - x1) ** 2 + (py - y1) ** 2) ** 0.5
    t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / l2))
    return ((px - (x1 + t * dx)) ** 2 + (py - (y1 + t * dy)) ** 2) ** 0.5

def in_check(x, y):
    return (dist_seg(x, y, *p1, *p2) <= lw or
            dist_seg(x, y, *p2, *p3) <= lw)

# ── 배경 라운드 코너 ──────────────────────────────────────────────────────────
R = int(SIZE * 0.18)

def in_bg(x, y):
    if x < R and y < R:
        return (x - R) ** 2 + (y - R) ** 2 <= R * R
    if x > SIZE - R and y < R:
        return (x - (SIZE - R)) ** 2 + (y - R) ** 2 <= R * R
    if x < R and y > SIZE - R:
        return (x - R) ** 2 + (y - (SIZE - R)) ** 2 <= R * R
    if x > SIZE - R and y > SIZE - R:
        return (x - (SIZE - R)) ** 2 + (y - (SIZE - R)) ** 2 <= R * R
    return True

# ── 렌더링 ────────────────────────────────────────────────────────────────────
BW = int(SIZE * 0.033)   # 방패 테두리 두께

print("아이콘 렌더링 중 (512×512)...")
pixels = []
for y in range(SIZE):
    row = []
    for x in range(SIZE):
        if not in_bg(x, y):
            row.append((0, 0, 0))       # 코너 바깥 → 투명 대신 배경색
        elif in_shield(x, y) and not in_shield(x, y, BW):
            row.append(GOLD)            # 방패 테두리
        elif in_shield(x, y, BW):
            row.append(GOLD if in_check(x, y) else DARK)   # 내부 + 체크
        else:
            row.append(BG)              # 앱 배경
    pixels.append(row)

base_png = "icon_base.png"
write_png(base_png, SIZE, SIZE, pixels)
print(f"  → {base_png} 생성")

# ── iconset 생성 ──────────────────────────────────────────────────────────────
iconset = "icon.iconset"
if os.path.exists(iconset):
    shutil.rmtree(iconset)
os.makedirs(iconset)

entries = [
    ("icon_16x16.png",       16),
    ("icon_16x16@2x.png",    32),
    ("icon_32x32.png",       32),
    ("icon_32x32@2x.png",    64),
    ("icon_128x128.png",    128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png",    256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png",    512),
]

for fname, sz in entries:
    dst = os.path.join(iconset, fname)
    subprocess.run(
        ["sips", "-z", str(sz), str(sz), base_png, "--out", dst],
        check=True, capture_output=True
    )
    print(f"  → {fname}")

# ── icns 변환 ─────────────────────────────────────────────────────────────────
subprocess.run(["iconutil", "-c", "icns", iconset, "-o", "icon.icns"],
               check=True)
print("\nicon.icns 생성 완료!")
