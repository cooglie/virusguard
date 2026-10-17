#!/usr/bin/env python3
"""Generiert das VirusGuard-App-Icon (1024x1024 PNG) mit PIL."""
from PIL import Image, ImageDraw, ImageFilter

SIZE = 1024
cx, cy = SIZE // 2, SIZE // 2

img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
grad = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
gdraw = ImageDraw.Draw(grad)
for y in range(SIZE):
    t = y / SIZE
    r = int(18 + (10 - 18) * t)
    g = int(40 + (120 - 40) * t)
    b = int(90 + (140 - 90) * t)
    gdraw.line([(0, y), (SIZE, y)], fill=(r, g, b, 255))
mask = Image.new("L", (SIZE, SIZE), 0)
ImageDraw.Draw(mask).rounded_rectangle([40, 40, SIZE - 40, SIZE - 40],
                                       radius=int(SIZE * 0.22), fill=255)
img.paste(grad, (0, 0), mask)

sw, sh = int(SIZE * 0.50), int(SIZE * 0.60)
sx = cx - sw // 2
sy = cy - sh // 2 + int(SIZE * 0.02)
shield_pts = [
    (cx, sy),
    (sx + sw, sy + int(sh * 0.08)),
    (sx + sw, sy + int(sh * 0.50)),
    (cx, sy + sh),
    (sx, sy + int(sh * 0.50)),
    (sx, sy + int(sh * 0.08)),
]

shadow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
ImageDraw.Draw(shadow).polygon([(x + 6, y + 6) for x, y in shield_pts],
                               fill=(0, 0, 0, 90))
shadow = shadow.filter(ImageFilter.GaussianBlur(8))
img.alpha_composite(shadow)

shield_img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
ImageDraw.Draw(shield_img).polygon(shield_pts, fill=(245, 250, 255, 240))
img.alpha_composite(shield_img)
ImageDraw.Draw(img).polygon(shield_pts, outline=(220, 235, 250, 255), width=6)

cw = int(SIZE * 0.22)
ch = int(SIZE * 0.16)
ccx, ccy = cx, cy + int(SIZE * 0.01)
p1 = (ccx - cw // 2, ccy)
p2 = (ccx - int(cw * 0.12), ccy + ch // 2)
p3 = (ccx + cw // 2, ccy - ch // 2)
lw = int(SIZE * 0.045)
chk = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
cdraw = ImageDraw.Draw(chk)
cdraw.line([p1, p2], fill=(20, 130, 95, 255), width=lw, joint="curve")
cdraw.line([p2, p3], fill=(20, 130, 95, 255), width=lw, joint="curve")
for p in (p1, p2, p3):
    cdraw.ellipse([p[0] - lw // 2, p[1] - lw // 2, p[0] + lw // 2, p[1] + lw // 2],
                  fill=(20, 130, 95, 255))
img.alpha_composite(chk)

gloss = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
ImageDraw.Draw(gloss).rectangle([40, 40, SIZE - 40, int(SIZE * 0.40)],
                                fill=(255, 255, 255, 28))
top_mask = Image.new("L", (SIZE, SIZE), 0)
ImageDraw.Draw(top_mask).rounded_rectangle([40, 40, SIZE - 40, SIZE - 40],
                                           radius=int(SIZE * 0.22), fill=255)
img.paste(gloss, (0, 0), top_mask)

img.save("VirusGuard/Resources/AppIcon.png", "PNG")
print("OK 1024x1024")
