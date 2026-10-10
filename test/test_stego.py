from steganography.lsb import encode_image, decode_image


cover_image = "uploads/pic1.jpg"
output_image = "outputs/pic1_stego.png"


test_payload = {
    "message": "CryptoStego Test",
    "number": 12345
}


print("Encoding...")

encode_image(
    cover_image,
    test_payload,
    output_image
)

print("Encoding successful.")
print("Stego image:", output_image)


print("\nDecoding...")

decoded_payload = decode_image(output_image)

print("Decoded payload:")
print(decoded_payload)


if decoded_payload == test_payload:
    print("\n✅ STEGANOGRAPHY TEST PASSED")
else:
    print("\n❌ STEGANOGRAPHY TEST FAILED")