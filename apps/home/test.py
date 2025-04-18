from PIL import Image, ImageDraw, ImageFont

# Image dimensions
width, height = 148, 19

# Background color (CSS hex code) and text color
background_color = "#1e88e5"
text_color = "white"

# Create a new image with the specified background color
image = Image.new("RGB", (width, height), background_color)

# Initialize ImageDraw object to add text
draw = ImageDraw.Draw(image)

# Load a default font (you can specify a path to a TTF file if needed)
font = ImageFont.load_default()

# Text to display
text = "IPTABLES"

# Stretch the text horizontally by a scaling factor
scaling_factor = 1.5  # Increase width by 1.5 times

# Calculate the text width and height to center it
bbox = draw.textbbox((0, 0), text, font=font)  # Get bounding box of the text
text_width = bbox[2] - bbox[0]
text_height = bbox[3] - bbox[1]

# Apply scaling to the width
text_width *= scaling_factor

# Calculate position to center the stretched text
text_position = ((width - text_width) // 2, (height - text_height) // 2)

# Use a scaled font size to fit the stretched width
new_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size=int(font.size * scaling_factor))

# Add text to the image
draw.text(text_position, text, font=new_font, fill=text_color)

# Save the image
image.save("iptables_image_stretched.png")

# Optionally, display the image
image.show()
