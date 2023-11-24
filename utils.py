def truncate_after_sequence(ba, seq):
    index = ba.find(seq)
    if index != -1:
        return ba[:index + len(seq)]
    else:
        return ba

def int_to_bool(mark):
    return bool(mark)

def bytes_to_human_readable(num_bytes):
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} YB"

def shorten_filename(filename, max_length):
    if len(filename) <= max_length:
        return filename

    # Extract extension
    dot_index = filename.rfind('.')
    if dot_index == -1 or dot_index == 0:
        # No extension or hidden file without extension
        base_name = filename
        extension = ''
    else:
        base_name = filename[:dot_index]
        extension = filename[dot_index:]  # includes the dot

    # Calculate max base name length (account for ellipsis and extension)
    max_base_length = max_length - len(extension) - 3  # 3 for ellipsis

    # Shorten and concatenate
    return base_name[:max_base_length] + '...' + extension