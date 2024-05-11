from PIL import Image

image = Image.open('/home/apn/Documents/bi0s/my_git/bi0s/ctf/2024/volga/qr/qr.png')
w = image.width
h = image.height

new_image = Image.new(image.mode, image.size)
pixels = image.load()

for y in range(h):
    for x in range(w):
        pixel = pixels[x, y]
        print(pixel)
        # next_bit = generator.next_bit()
        # encrypted = pixel ^ next_bit

        # new_image.putpixel((x, y), encrypted * 255)

# new_image.save("qr_flag.png", image.format)
