import sys

def dec_string(string):
    try:
        # Initialize an empty string to store the results
        results = ""

        # Iterate over pairs of characters in the string
        for i in range(0, len(string)-1, 2):
            first_char = string[i]
            second_char = string[i+1]
            #ascii_val1 = ord(first_char)
            #ascii_val2 = ord(second_char)
            result = ((first_char - 65) * 26) + (second_char - 65)
            results += chr(result)
        # Print the results as a string
        # print(results)
        return results
    except:
        pass

XOR_KEY = bytes.fromhex('296ce19dd63913c0b5945ed144100c99684cb4470ba0d0d675d8f3dcb65ca68ab32bd9ff8d281921cc1effbce2f3d5b3a939a6949e1924c733a77eda759ad5228daa17988dcc0cded44d4d5f4be96e201f3f7d15fc09ab338e1aa33f95aed9b3fb76bd4a')

if len(sys.argv) != 2:
    print("Error: Please specify the target file name as an argument.")
    sys.exit()

file_name = sys.argv[1]

with open(file_name, "rb") as f:
    # Check the character at the end of the file is "*"
    last_char = f.read()[-1]
    if chr(last_char) == '*':
        print("Highly likely crafted RustBucket PDF file.")
    else:
        print("It doesn't seem like a crafted RustBucket PDF file.")

    # Read four-byte hexadecimal value from the final five bytes of the file, XOR with the value 0x184ADB34.
    f.seek(-5, 2)
    config_offset = int.from_bytes(f.read(4), byteorder='little') ^ 0x184ADB34
    print(f"config offset is:" + hex(config_offset))

    # Read 4 bytes and XOR with 0x47A83D40 to acquire offset of pdf file.
    f.seek(config_offset, 0)
    pdf_offset = int.from_bytes(f.read(4), byteorder='little') ^ 0x47A83D40
    print(f"pdf_offset is:" + hex(pdf_offset))

    # Read the next 4 bytes, XOR with 0xA5EC6732 to acquire size of pdf file.
    pdf_size = int.from_bytes(f.read(4), byteorder='little') ^ 0xA5EC6732
    print(f"pdf_size is:" + hex(pdf_size))

    # Read the next 4 bytes, XOR with 0x14738D8F to acquire offset of C2
    c2_offset = int.from_bytes(f.read(4), byteorder='little') ^ 0x14738D8F
    print(f"c2_offset:" + hex(c2_offset))
    
    # Read the next 4 bytes, XOR with 0xC589FD0A to acquire length of C2.
    c2_length = int.from_bytes(f.read(4), byteorder='little') ^ 0xC589FD0A
    print(f"c2_length:" + hex(c2_length))

    # XOR the C2 with the XOR_KEY
    f.seek(c2_offset, 0)
    c2_data = bytearray(f.read(c2_length))
    for i in range(c2_length):
        c2_data[i] ^= XOR_KEY[i % len(XOR_KEY)]

print(f"Extracted C2 address is: " + c2_data.decode("utf-8"))