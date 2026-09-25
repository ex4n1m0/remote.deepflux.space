// Generates the app icon source PNG (1024x1024) with no external deps
// (raw RGBA + zlib). Output: src-tauri/icons/source.png — then
// `pnpm tauri icon src-tauri/icons/source.png` derives the full set.
// Kept as a script so the icon is reproducible from code.
import { deflateSync } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SIZE = 1024;
const px = new Uint8Array(SIZE * SIZE * 4);

const put = (x, y, r, g, b, a = 255) => {
  const i = (y * SIZE + x) * 4;
  const sa = a / 255;
  const da = px[i + 3] / 255;
  const outA = sa + da * (1 - sa);
  if (outA <= 0) return;
  px[i] = Math.round((r * sa + px[i] * da * (1 - sa)) / outA);
  px[i + 1] = Math.round((g * sa + px[i + 1] * da * (1 - sa)) / outA);
  px[i + 2] = Math.round((b * sa + px[i + 2] * da * (1 - sa)) / outA);
  px[i + 3] = Math.round(outA * 255);
};

const fillRoundRect = (cx, cy, w, h, radius, color) => {
  const x0 = Math.round(cx - w / 2);
  const x1 = Math.round(cx + w / 2);
  const y0 = Math.round(cy - h / 2);
  const y1 = Math.round(cy + h / 2);
  for (let y = y0; y < y1; y++) {
    for (let x = x0; x < x1; x++) {
      const dx = x < x0 + radius ? x0 + radius - x : x > x1 - radius ? x - (x1 - radius) : 0;
      const dy = y < y0 + radius ? y0 + radius - y : y > y1 - radius ? y - (y1 - radius) : 0;
      if (dx * dx + dy * dy <= radius * radius) put(x, y, ...color);
    }
  }
};

const fillRect = (x0, y0, w, h, color) => {
  for (let y = y0; y < y0 + h; y++) for (let x = x0; x < x0 + w; x++) put(x, y, ...color);
};

// Background: deep slate rounded square.
fillRoundRect(SIZE / 2, SIZE / 2, SIZE - 64, SIZE - 64, 180, [15, 23, 42]);
// Two "screens": host (upper-left) and controller (lower-right).
fillRoundRect(330, 360, 460, 320, 36, [30, 41, 59]);
fillRect(520, 656, 80, 44, [51, 65, 85]); // host stand
fillRoundRect(330, 360, 428, 264, 24, [56, 189, 248]); // host screen lit
fillRoundRect(700, 690, 300, 210, 30, [30, 41, 59]);
fillRect(830, 888, 40, 34, [51, 65, 85]); // controller stand
fillRoundRect(700, 690, 276, 164, 20, [125, 211, 252]); // controller screen lit
// Link: diagonal line between the two screens.
for (let t = 0; t <= 1.001; t += 0.002) {
  const x = Math.round(430 + (560 - 430) * t);
  const y = Math.round(640 + (760 - 640) * t);
  for (let o = -12; o <= 12; o++) put(x + o, y, 148, 163, 184);
}
// Link nodes.
fillRoundRect(430, 640, 64, 64, 32, [226, 232, 240]);
fillRoundRect(560, 760, 64, 64, 32, [226, 232, 240]);

// --- minimal PNG encoder (RGBA8, no filtering) ---
const crcTable = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0);
ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // RGBA
const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
for (let y = 0; y < SIZE; y++) {
  raw[y * (SIZE * 4 + 1)] = 0; // filter none
  Buffer.from(px.buffer, y * SIZE * 4, SIZE * 4).copy(raw, y * (SIZE * 4 + 1) + 1);
}
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk("IHDR", ihdr),
  chunk("IDAT", deflateSync(raw, { level: 9 })),
  chunk("IEND", Buffer.alloc(0)),
]);

const out = join(dirname(fileURLToPath(import.meta.url)), "../src-tauri/icons/source.png");
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, png);
console.log(`wrote ${out} (${png.length} bytes)`);
