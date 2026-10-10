from PIL import Image
import pickle
import struct


# ============================================================
# SERIALIZE PAYLOAD
# ============================================================

def serialize_payload(payload):
    """
    Convert the payload dictionary into bytes.
    This is the exact data that will be hidden inside
    the cover image.
    """

    return pickle.dumps(payload)


# ============================================================
# CALCULATE PAYLOAD SIZE
# ============================================================

def calculate_payload_size(payload):
    """
    Return the exact number of bytes required to store
    the serialized payload.
    """

    data = serialize_payload(payload)

    return len(data)


# ============================================================
# CALCULATE IMAGE CAPACITY
# ============================================================

def calculate_image_capacity(image):
    """
    Calculate the number of bits available for LSB
    steganography.

    RGB image:
        3 bits per pixel
    """

    image = image.convert("RGB")

    return (
        image.width
        * image.height
        * 3
    )


# ============================================================
# ENCODE IMAGE
# ============================================================

def encode_image(
    image_path,
    payload,
    output_path
):

    # --------------------------------------------------------
    # Open image
    # --------------------------------------------------------

    image = Image.open(
        image_path
    )

    image = image.convert(
        "RGB"
    )


    # --------------------------------------------------------
    # Convert payload to bytes
    # --------------------------------------------------------

    data = serialize_payload(
        payload
    )


    # --------------------------------------------------------
    # Store payload length in first 4 bytes
    # --------------------------------------------------------

    header = struct.pack(
        ">I",
        len(data)
    )


    # --------------------------------------------------------
    # Combine header + payload
    # --------------------------------------------------------

    full_data = (
        header
        + data
    )


    # --------------------------------------------------------
    # Convert bytes to binary
    # --------------------------------------------------------

    binary_data = "".join(
        format(byte, "08b")
        for byte in full_data
    )


    # --------------------------------------------------------
    # Calculate image capacity
    # --------------------------------------------------------

    capacity = calculate_image_capacity(
        image
    )


    # --------------------------------------------------------
    # Display information
    # --------------------------------------------------------

    print("====================================")
    print("STEGANOGRAPHY CAPACITY CHECK")
    print(
        "Image:",
        image.width,
        "x",
        image.height
    )

    print(
        "Capacity:",
        capacity,
        "bits"
    )

    print(
        "Required:",
        len(binary_data),
        "bits"
    )

    print(
        "Payload:",
        len(data),
        "bytes"
    )


    # --------------------------------------------------------
    # Capacity validation
    # --------------------------------------------------------

    if len(binary_data) > capacity:

        raise Exception(
            "Cover image is too small. "
            f"Required {len(binary_data)} bits, "
            f"but image can hold only "
            f"{capacity} bits."
        )


    print(
        "Capacity check: PASSED"
    )


    # --------------------------------------------------------
    # Write data into LSB
    # --------------------------------------------------------

    data_index = 0

    pixels = image.load()


    for y in range(
        image.height
    ):

        for x in range(
            image.width
        ):

            r, g, b = pixels[x, y]

            rgb = [
                r,
                g,
                b
            ]


            for i in range(3):

                if data_index < len(binary_data):

                    rgb[i] = (
                        rgb[i] & ~1
                    ) | int(
                        binary_data[data_index]
                    )

                    data_index += 1


            pixels[x, y] = tuple(
                rgb
            )


            # Stop when complete payload
            # has been written

            if data_index >= len(binary_data):

                break


        if data_index >= len(binary_data):

            break


    # --------------------------------------------------------
    # Save stego image
    # --------------------------------------------------------

    image.save(
        output_path,
        format="PNG"
    )


    print(
        "Encoding completed."
    )

    print(
        "Output:",
        output_path
    )

    print("====================================")


# ============================================================
# DECODE IMAGE
# ============================================================

def decode_image(
    image_path
):

    # --------------------------------------------------------
    # Open image
    # --------------------------------------------------------

    image = Image.open(
        image_path
    )

    image = image.convert(
        "RGB"
    )


    pixels = image.load()


    # --------------------------------------------------------
    # Extract LSB bits
    # --------------------------------------------------------

    binary_data = ""


    for y in range(
        image.height
    ):

        for x in range(
            image.width
        ):

            r, g, b = pixels[x, y]


            for color in [
                r,
                g,
                b
            ]:

                binary_data += str(
                    color & 1
                )


    # --------------------------------------------------------
    # Check header
    # --------------------------------------------------------

    if len(binary_data) < 32:

        raise Exception(
            "Hidden data is corrupted or incomplete."
        )


    # --------------------------------------------------------
    # Extract first 32 bits
    # --------------------------------------------------------

    header_bits = binary_data[
        :32
    ]


    header_bytes = bytes(
        int(
            header_bits[i:i + 8],
            2
        )
        for i in range(
            0,
            32,
            8
        )
    )


    # --------------------------------------------------------
    # Read payload length
    # --------------------------------------------------------

    payload_length = struct.unpack(
        ">I",
        header_bytes
    )[0]


    print("====================================")
    print(
        "STEGANOGRAPHY DECODING"
    )

    print(
        "Payload length:",
        payload_length,
        "bytes"
    )


    # --------------------------------------------------------
    # Calculate required bits
    # --------------------------------------------------------

    payload_bits_length = (
        payload_length
        * 8
    )


    total_required_bits = (
        32
        + payload_bits_length
    )


    # --------------------------------------------------------
    # Validate payload
    # --------------------------------------------------------

    if (
        total_required_bits
        > len(binary_data)
    ):

        raise Exception(
            "Hidden data is corrupted or incomplete."
        )


    # --------------------------------------------------------
    # Extract payload bits
    # --------------------------------------------------------

    payload_bits = binary_data[
        32:total_required_bits
    ]


    # --------------------------------------------------------
    # Convert binary to bytes
    # --------------------------------------------------------

    hidden_data = bytes(
        int(
            payload_bits[i:i + 8],
            2
        )
        for i in range(
            0,
            len(payload_bits),
            8
        )
    )


    # --------------------------------------------------------
    # Deserialize payload
    # --------------------------------------------------------

    try:

        payload = pickle.loads(
            hidden_data
        )

    except Exception:

        raise Exception(
            "Hidden data is corrupted or incomplete."
        )


    print(
        "Decoding successful."
    )

    print("====================================")


    return payload