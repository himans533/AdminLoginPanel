from PIL import Image

def process_logo():
    try:
        # Open original
        img = Image.open('static/lg.png').convert("RGBA")
        datas = img.getdata()

        newData = []
        for item in datas:
            # item is (r, g, b, a)
            r, g, b, a = item

            # White background removal
            if r > 220 and g > 220 and b > 220:
                newData.append((255, 255, 255, 0))
            
            # Dark text to White
            # Strict dark check: typical black/dark grey
            elif r < 80 and g < 80 and b < 80:
                newData.append((255, 255, 255, a)) # Keep original alpha if any
            else:
                newData.append(item)

        img.putdata(newData)
        
        # Crop to content
        bbox = img.getbbox()
        if bbox:
            img = img.crop(bbox)
            
        img.save('static/logo_processed.png', "PNG")
        print("Logo processed successfully: static/logo_processed.png")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    process_logo()
