from PIL import Image, ImageFont, ImageDraw
import random

def draw_label(name):
	font_path = "ethnocentric.otf"
	font_size = 30
	font = ImageFont.truetype(font_path, font_size)
	text_x = 10
	text_y = 5

	img = Image.new('RGBA', (60, 30), color = (30, 60, 110, 255))
	colored_bg = Image.new('RGBA', (60, 30), color = (30, 60, 110, 255))
	draw = ImageDraw.Draw(img)
	width = int(draw.textlength(name, font=font)) + 20

	img = Image.new('RGBA', (width, font_size + 20), color = (30, 60, 110, 0))
	colored_bg = Image.new('RGBA', (width, font_size + 20), color = (30, 60, 110, 0))
	draw = ImageDraw.Draw(img)

	# transparency values of text frames
	transparency_values = [255, 80, 70, 60, 50, 40, 30]

	r = random.randint(1, 200)
	r2 = random.randint(10, 40)
	for i in range(len(transparency_values)):
		draw = ImageDraw.Draw(img)

		draw.text((text_x, text_y), name, (r, 255, 100, transparency_values[i]), 
				font=font, stroke_width=i+1)
		draw.text((text_x, text_y), name, font=font, fill=(r+r2, 255, 150))

		colored_bg = Image.alpha_composite(colored_bg, img)

		img = Image.new('RGBA', colored_bg.size, (255, 255, 255, 0))

	return colored_bg
