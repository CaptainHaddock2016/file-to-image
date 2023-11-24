# file-to-image
Image-Based File Encoding and Decoding Program This Python program handles the encoding and decoding of files into images of GIFs (PNG and GIF). It comes with a simple GUI (WIP) to encode and decode a file into a single image or multiple. This program could be used for storing data on image sharing services like Imgur or Flickr.

Note that this project is still being developed and by no means stable. Currently the GUI only works on Windows.

Key Features:

File Encryption/Decryption: Utilizes AES-GCM for robust encryption and decryption, with password-based key derivation (PBKDF2). Image-Based Encoding: Encodes any file (binary or text) into PNG or GIF images, storing data in the pixel values. Flexible Data Retrieval: Decodes data from single PNG images or sequences of PNGs/GIFs, reconstructing the original file. Custom Headers: Implements headers for metadata, including file name, size, and encryption status for quickly gathering file metadata without decoding the entire file.
