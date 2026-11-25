"""Regenerate the Win32 gauge icon resources using only the Python standard library."""
import math
import struct
import zlib
from pathlib import Path

ICONS = Path(__file__).resolve().parents[1] / "client/windows/icons"


def png(size, fraction):
    angle = math.radians(200 - 220 * fraction)
    dx, dy = math.cos(angle), -math.sin(angle)
    samples = 3 if size < 96 else 2
    data = bytearray()
    for y in range(size):
        data.append(0)
        for x in range(size):
            rgb = [0, 0, 0]
            opaque = 0
            for sy in range(samples):
                for sx in range(samples):
                    u = (x + (sx + .5) / samples) / size
                    v = (y + (sy + .5) / samples) / size
                    if math.hypot(max(abs(u-.5)-.31, 0), max(abs(v-.5)-.31, 0)) > .16:
                        continue
                    color = (13, 39, 55)
                    px, py = u-.5, v-.62
                    radius = math.hypot(px, py)
                    theta = math.degrees(math.atan2(-py, px)) % 360
                    if .305 < radius < .396 and (theta <= 200 or theta >= 340):
                        color = (55, 211, 187) if theta >= 42 and theta <= 200 else (251, 175, 70)
                    along, across = px*dx+py*dy, abs(py*dx-px*dy)
                    if (0 <= along <= .312 and across <= .043*(1-along/.34)) or radius < .072:
                        color = (248, 251, 252)
                    opaque += 1
                    for i in range(3):
                        rgb[i] += color[i]
            data.extend(round(c/opaque) if opaque else 0 for c in rgb)
            data.append(round(255*opaque/(samples*samples)))

    def chunk(kind, body):
        return struct.pack(">I", len(body))+kind+body+struct.pack(">I", zlib.crc32(kind+body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">2I5B",size,size,8,6,0,0,0))
            + chunk(b"IDAT",zlib.compress(data,9)) + chunk(b"IEND",b""))


def icon(name, sizes, position):
    images = [png(size, position) for size in sizes]
    directory = bytearray(struct.pack("<3H", 0, 1, len(sizes)))
    offset = 6 + 16 * len(sizes)
    for size, image in zip(sizes, images):
        directory.extend(struct.pack("<4B2H2I", size % 256, size % 256, 0, 0, 1, 32, len(image), offset))
        offset += len(image)
    (ICONS / name).write_bytes(directory + b"".join(images))


if __name__ == "__main__":
    ICONS.mkdir(exist_ok=True)
    icon("app.ico", (16, 20, 24, 32, 40, 48, 64, 128, 256), .72)
    for step in range(21):
        icon(f"live-{step:02}.ico", (16, 24, 32, 48), step/20)
