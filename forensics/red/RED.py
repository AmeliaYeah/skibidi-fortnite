from PIL import Image

#image metadata has poem. check the first letter of each line, says CHECK LSB
#hint also says check RGBA


def extract_lsb_all(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata()) #store all the pixels in a list
    bit_string = "" #accumulate the least significant bits
    for pixel in pixels:
        for color in pixel:
            bit_string += bin(color)[-1] #get the least significant bit
    #group bits into bytes
    byte_chunks = [bit_string[i:i+8] for i in range(0, len(bit_string), 8)]
    decoded_chars = []
    for byte in byte_chunks:
        if len(byte) == 8:
            num = int(byte, 2)
            #append only if in printable range, else use placeholder
            if 32 <= num <= 126:
                decoded_chars.append(chr(num))
            else:
                decoded_chars.append('?')
    decoded_message = "".join(decoded_chars)
    return decoded_message

if __name__ == "__main__":
    message = extract_lsb_all("shared/red.png")
    print("Hidden message:", message)
