from PIL import Image
import math
import utils
import os
import zlib
import requests
import imageio
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

TYPE = "png"

HEADER_EOF = b"xff\xfe\xfd"

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100000)

def encrypt_data(data, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_data(encrypted_data, password):
    data = base64.b64decode(encrypted_data)
    salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except:
        raise ValueError("MAC check failed. The file has been tampered with or the password is incorrect.")

def from_url(url):
    data = requests.get(url)
    datatype = data.headers['Content-Type']
    if "png" in datatype:
        decode_from_bytes(data.content)
    elif "gif" in datatype:
        decode_file_from_gif(data.content)
    else:
        raise ValueError("Invalid File type")

def create_header(file_name, file_bytes, original_file_size, encrypted):
    file_name_encoded = file_name.encode()
    header = bytearray()
    header.append(len(file_name_encoded)) # File name length
    header.extend(file_name_encoded)       # File name
    header.extend(len(file_bytes).to_bytes(8, 'big')) # Encrypted file size (8 bytes)
    header.extend(original_file_size.to_bytes(8, 'big')) # Original file size (8 bytes)
    header.append(encrypted) # Encrypted flag
    header.extend(HEADER_EOF)
    return header

def read_header(bytearray):
    file_name_length = bytearray[0]
    file_name_end = 1 + file_name_length
    file_name = bytearray[1:file_name_end].decode()
    
    file_size_index = file_name_end
    file_size = int.from_bytes(bytearray[file_size_index:file_size_index+8], 'big') # Reading 8 bytes for file size

    original_file_size_index = file_size_index + 8
    original_file_size = int.from_bytes(bytearray[original_file_size_index:original_file_size_index+8], 'big') # Reading 8 bytes for original file size

    encrypted = bytearray[original_file_size_index+8]

    return file_name, file_size, original_file_size, encrypted

def get_header_from_image(image_dir):

    image_files = sorted([f for f in os.listdir(image_dir) if f.endswith(f'.{TYPE}')])
    if not image_files:
        raise FileNotFoundError("No image files found in the specified directory.")

    first_image_file = image_files[0]

    with Image.open(os.path.join(image_dir, first_image_file)) as image:
        pixels = image.load()

    extracted_bytes = bytearray()
    for y in range(image.size[1]):
        for x in range(image.size[0]):
            pixel = pixels[x, y]
            extracted_bytes.extend(pixel[:3])

        if HEADER_EOF in extracted_bytes:
            break
        else:
            continue

    header_data = extracted_bytes[8:-len(HEADER_EOF)]
    
    file_name, file_size, original_file_size, encrypted = read_header(header_data)

    return file_name, file_size, original_file_size, encrypted

def num_frames(path, image_resolution):
    with open(path, 'rb') as file:
        file_bytes = file.read()

    header = create_header(os.path.basename(path), file_bytes, len(file_bytes), False)
    data = header + zlib.compress(file_bytes, 1)
    
    data = len(data).to_bytes(8, 'big') + data
        
    bytes_per_image = image_resolution[0] * image_resolution[1] * 3
    
    return math.ceil(len(data) / bytes_per_image)

def num_frames_decode(path):
    return len(sorted([f for f in os.listdir(path) if f.endswith(f'.{TYPE}')]))

def encode_file_in_images(file_path, output_dir, image_resolution, password=None, progressfunc=None):
    
    encrypted = bool(password)
    with open(file_path, 'rb') as file:
        file_bytes = file.read()
        
    fsize = len(file_bytes)
    if encrypted:
        file_bytes = encrypt_data(file_bytes, password).encode()
    
    file_bytes = zlib.compress(file_bytes, 1)
            
    encrypted = bool(password)
    header = create_header(os.path.basename(file_path), file_bytes, fsize, encrypted)

    data = header + file_bytes
    
    data = len(data).to_bytes(8, 'big') + data
        
    bytes_per_image = image_resolution[0] * image_resolution[1] * 3
    num_images = math.ceil(len(data) / bytes_per_image)

    for img_index in range(num_images):
        start_byte = img_index * bytes_per_image
        end_byte = start_byte + bytes_per_image
        image_bytes = data[start_byte:end_byte]

        image = Image.new('RGB', image_resolution)
        pixels = image.load()

        byte_index = 0
        for y in range(image_resolution[1]):
            for x in range(image_resolution[0]):
                if byte_index < len(image_bytes) - 2:
                    pixels[x, y] = (image_bytes[byte_index], image_bytes[byte_index + 1], image_bytes[byte_index + 2])
                    byte_index += 3
                elif byte_index < len(image_bytes) - 1:
                    pixels[x, y] = (image_bytes[byte_index], image_bytes[byte_index + 1], 0)
                    byte_index += 2
                elif byte_index < len(image_bytes):
                    pixels[x, y] = (image_bytes[byte_index], 0, 0)
                    byte_index += 1
                else:
                    pixels[x, y] = (0, 0, 0)
                    
        if progressfunc:
            progressfunc()

        image.save(os.path.join(output_dir, f'encoded_{img_index}.{TYPE}'))
        
def decode_from_bytes(imgData, password=None):
    image = Image.open(imgData)
    pixels = image.load()
    
    all_extracted_bytes = []
    for y in range(image.size[1]):
        for x in range(image.size[0]):
            pixel = pixels[x, y]
            all_extracted_bytes.extend(pixel[:3])
        
    data_length = int.from_bytes(all_extracted_bytes[:8], 'big')
    extracted_data = bytearray(all_extracted_bytes[8:8+data_length])

    file_name, file_name_end, file_size, _, encrypted = read_header(extracted_data)
    encrypted = utils.int_to_bool(encrypted)
        
    file_data = zlib.decompress(extracted_data[extracted_data.index(HEADER_EOF) + len(HEADER_EOF):])
    
    if encrypted:
        if not password:
            raise ValueError("Password required for decryption.")
        file_data = decrypt_data(file_data, password)

    with open(file_name, 'wb') as file:
        file.write(file_data)
    
def decode_file_from_images(image_dir, save_path, password=None, progressfunc=None):
    image_files = sorted([f for f in os.listdir(image_dir) if f.endswith(f'.{TYPE}')])

    all_extracted_bytes = []
    for image_file in image_files:
        image = Image.open(os.path.join(image_dir, image_file))
        pixels = image.load()

        for y in range(image.size[1]):
            for x in range(image.size[0]):
                pixel = pixels[x, y]
                all_extracted_bytes.extend(pixel[:3])
                
        if progressfunc:
            progressfunc()

    data_length = int.from_bytes(all_extracted_bytes[:8], 'big')
    extracted_data = bytearray(all_extracted_bytes[8:8+data_length])

    file_name, _, _, encrypted = read_header(extracted_data)
    encrypted = utils.int_to_bool(encrypted)
        
    file_data = zlib.decompress(extracted_data[extracted_data.index(HEADER_EOF) + len(HEADER_EOF):])
    
    if encrypted:
        if not password:
            raise ValueError("Password required for decryption.")
        try:
            file_data = decrypt_data(file_data, password)
        except:
            return False

    pathtosave = file_name
    if save_path:
        pathtosave = save_path
        
    with open(pathtosave, 'wb') as file:
        file.write(file_data)
        
    return True
        
def encode_file_in_gif(file_path, output_path, image_resolution, password=None, progressfunc=None):
    encrypted = bool(password)
    with open(file_path, 'rb') as file:
        file_bytes = file.read()
        
    fsize = len(file_bytes)
    if encrypted:
        file_bytes = encrypt_data(file_bytes, password).encode()
    
    file_bytes = zlib.compress(file_bytes, 1)
        
    header = create_header(os.path.basename(file_path), file_bytes, fsize, encrypted)

    data = header + file_bytes
    data = len(data).to_bytes(8, 'big') + data

    bytes_per_frame = image_resolution[0] * image_resolution[1]
    num_frames = math.ceil(len(data) / bytes_per_frame)
    
    with imageio.get_writer(output_path, mode='I', format='GIF', palettesize=256) as writer:
        for frame_index in range(num_frames):
            start_byte = frame_index * bytes_per_frame
            end_byte = start_byte + bytes_per_frame
            frame_data = data[start_byte:end_byte]
            image = Image.new('L', image_resolution)
            image.putdata(frame_data)
            writer.append_data(image)
            
            if progressfunc:
                progressfunc()
    
def decode_file_from_gif(gif_path, password=None):
    gif = imageio.mimread(gif_path, memtest=False)

    all_extracted_bytes = bytearray()
    data_length = 0
    retrieved_length = False
    
    for frame in gif:
        pil_image = Image.fromarray(frame)
        rgb_frame = pil_image.convert('L')
        for byte_value in rgb_frame.getdata():
            all_extracted_bytes.append(byte_value)
            if not retrieved_length and len(all_extracted_bytes) >= 8:
                data_length = int.from_bytes(all_extracted_bytes[:8], 'big')
                retrieved_length = True
            if len(all_extracted_bytes) - 8 >= data_length:
                break
        else:
            continue
        break

    extracted_data = all_extracted_bytes[8:8 + data_length]

    file_name, file_size, _, encrypted = read_header(extracted_data)
    encrypted = bool(encrypted)
    file_data = zlib.decompress(extracted_data[extracted_data.index(HEADER_EOF) + len(HEADER_EOF):])
    
    if encrypted:
        if not password:
            raise ValueError("Password required for decryption.")
        file_data = decrypt_data(file_data, password)

    with open(file_name, 'wb') as file:
        file.write(file_data)


def embed_data_in_image(image_path, data, output_path, password=None):
    from pillow_heif import register_heif_opener
    register_heif_opener()

    encrypted_data = encrypt_data(data.encode(), password).encode() if password else data

    compressed_data = zlib.compress(encrypted_data)

    with Image.open(image_path) as img:
        img = img.convert('RGB')
        pixels = img.load()

        total_pixels = img.size[0] * img.size[1]

        if len(compressed_data) * 8 > total_pixels:
            raise ValueError("Not enough space in the image to store the data")

        data_bits = list(map(int, ''.join([bin(byte)[2:].zfill(8) for byte in compressed_data])))
        data_index = 0
        for y in range(img.size[1]):
            for x in range(img.size[0]):
                if data_index < len(data_bits):
                    pixel = list(pixels[x, y])
                    for n in range(3): 
                        if data_index < len(data_bits):
                            pixel[n] = pixel[n] & ~1 | data_bits[data_index]
                            data_index += 1
                    pixels[x, y] = tuple(pixel)

    img.save(output_path, 'PNG')
    
def extract_data_from_image(image_path, password=None):

    with Image.open(image_path) as img:
        img = img.convert('RGB')
        pixels = img.load()

        data_bits = []
        for y in range(img.size[1]):
            for x in range(img.size[0]):
                for n in range(3):
                    data_bits.append(pixels[x, y][n] & 1)

        data_bytes = bytearray(int(''.join(map(str, data_bits[i:i+8])), 2) for i in range(0, len(data_bits), 8))

    decompressed_data = zlib.decompress(data_bytes)

    decrypted_data = decrypt_data(decompressed_data, password) if password else decompressed_data

    return decrypted_data
