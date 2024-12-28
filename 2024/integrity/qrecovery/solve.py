from PIL import Image, ImageDraw
import os

# Load the obscured QR code
obscured_path = "obscured.png"
qr_code_image = Image.open(obscured_path)
width, height = qr_code_image.size
half_width, half_height = width // 2, height // 2

# Define the coordinates for the four quadrants
squares = {
    "1": (0, 0, half_width, half_height),
    "2": (half_width, 0, width, half_height),
    "3": (0, half_height, half_width, height),
    "4": (half_width, half_height, width, height),
}

# Function to split each quadrant into two triangles
def split_square_into_triangles(img, box):
    x0, y0, x1, y1 = box
    a_triangle_points = [(x0, y0), (x1, y0), (x0, y1)]
    b_triangle_points = [(x1, y1), (x1, y0), (x0, y1)]

    def crop_triangle(points):
        mask = Image.new("L", img.size, 0)
        draw = ImageDraw.Draw(mask)
        draw.polygon(points, fill=255)
        triangle_img = Image.new("RGBA", img.size)
        triangle_img.paste(img, (0, 0), mask)
        return triangle_img.crop((x0, y0, x1, y1))

    return crop_triangle(a_triangle_points), crop_triangle(b_triangle_points)

# Split the quadrants into triangles
triangle_images = {}
for key, box in squares.items():
    triangle_images[f"{key}a"], triangle_images[f"{key}b"] = split_square_into_triangles(
        qr_code_image, box)

# Iterate through all possible 4-digit PINs (0000–9999)
output_folder = "reconstructed_qr_codes"
os.makedirs(output_folder, exist_ok=True)

for pin in range(10000):
    pin_str = f"{pin:04}"  # Format PIN as 4 digits
    a_order = list(pin_str)  # Order for 'a' triangles based on the PIN
    b_order = list(pin_str[::-1])  # Order for 'b' triangles is the reverse of the PIN

    # Create a new blank image for the reconstructed QR code
    reconstructed_image = Image.new("RGBA", qr_code_image.size)

    # Define positions for each quadrant
    final_positions = [
        (0, 0),
        (half_width, 0),
        (0, half_height),
        (half_width, half_height),
    ]

    # Reconstruct the QR code
    for i in range(4):
        a_triangle = triangle_images[f"{a_order[i]}a"]
        b_triangle = triangle_images[f"{b_order[i]}b"]
        combined_square = Image.new("RGBA", (half_width, half_height))
        combined_square.paste(a_triangle, (0, 0))
        combined_square.paste(b_triangle, (0, 0), b_triangle)
        reconstructed_image.paste(combined_square, final_positions[i])

    # Save the reconstructed QR code for this PIN
    output_path = os.path.join(output_folder, f"reconstructed_{pin_str}.png")
    reconstructed_image.save(output_path)

print(f"Reconstruction complete. Check the '{output_folder}' folder for results.")
