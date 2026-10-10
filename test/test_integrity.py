import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from steganography.lsb import encode_image, decode_image
from security.integrity import generate_hash


# ---------------------------------------
# 1. Create original data
# ---------------------------------------

original_data = b"This is my original confidential document."

original_hash = generate_hash(original_data)

print("Original Hash:")
print(original_hash)


# ---------------------------------------
# 2. Create payload
# ---------------------------------------

payload = {
    "ciphertext": original_data,
    "hash": original_hash,
    "filename": "sample.txt"
}


# ---------------------------------------
# 3. Encode payload
# ---------------------------------------

cover_image = "uploads/pic1.jpg"
output_image = "outputs/integrity_test.png"

encode_image(
    cover_image,
    payload,
    output_image
)

print("\nStego image created successfully.")


# ---------------------------------------
# 4. Decode payload
# ---------------------------------------

decoded_payload = decode_image(output_image)

stored_hash = decoded_payload["hash"]
recovered_data = b"This file has been modified!"

print("\nStored Hash:")
print(stored_hash)


# ---------------------------------------
# 5. Calculate hash again
# ---------------------------------------

calculated_hash = generate_hash(recovered_data)

print("\nCalculated Hash:")
print(calculated_hash)


# ---------------------------------------
# 6. Verify integrity
# ---------------------------------------

if calculated_hash == stored_hash:

    print("\n✅ INTEGRITY TEST PASSED")

else:

    print("\n❌ INTEGRITY TEST FAILED")