from PIL import Image

SOURCE = "outputs/pic1_stego.png"
TAMPERED = "outputs/pic1_tampered.png"

# Open the successfully encrypted stego image
image = Image.open(SOURCE).convert("RGB")
pixels = image.load()

# Change ONE LSB in the first pixel.
# This deliberately modifies one hidden bit.
r, g, b = pixels[0, 0]

r = r ^ 1

pixels[0, 0] = (r, g, b)

# Save as PNG so the pixel data is preserved
image.save(TAMPERED, format="PNG")

print("Original :", SOURCE)
print("Tampered :", TAMPERED)
print("✅ One LSB was modified.")