from PIL import Image
import os

def convert_to_ico(input_file, output_file, size=(256, 256)):
    """Convert an image file to ICO format for use as application icon"""
    try:
        # Open the image
        img = Image.open(input_file)
        
        # Resize to required size while maintaining aspect ratio
        img.thumbnail(size, Image.Resampling.LANCZOS)
        
        # Create new image with alpha channel (transparency)
        icon = Image.new("RGBA", img.size)
        
        # Paste the original image
        if img.mode == "RGBA":
            icon = img
        else:
            icon.paste(img)
        
        # Save as ICO
        icon.save(output_file, format='ICO')
        print(f"Successfully converted {input_file} to {output_file}")
        return True
    except Exception as e:
        print(f"Error converting image: {e}")
        return False

if __name__ == "__main__":
    if os.path.exists('logo.jpg'):
        success = convert_to_ico('logo.jpg', 'app_icon.ico')
        if success:
            print("Now you can use app_icon.ico in your PyInstaller spec file")
    else:
        print("logo.jpg not found in the current directory") 