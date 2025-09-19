import os
import subprocess
import hashlib
from datetime import datetime
import exifread
import magic

def memory_acquisition():
    print("Acquiring memory...")
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"memory_dump_{timestamp}.mem"
        
        result = subprocess.run(["sudo", "dd", "if=/dev/mem", f"of={output_file}", "bs=1M"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Memory dump saved to {output_file}")
        else:
            print("Memory acquisition failed")
    except:
        print("Memory acquisition requires root privileges")

def create_disk_image(device):
    print(f"Creating disk image of {device}")
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"disk_image_{timestamp}.img"
        
        result = subprocess.run(["sudo", "dd", f"if={device}", f"of={output_file}", "bs=4M", "status=progress"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Disk image saved to {output_file}")
        else:
            print("Disk imaging failed")
    except:
        print("Disk imaging requires root privileges")

def recover_files(path):
    print(f"Recovering deleted files from {path}")
    try:
        result = subprocess.run(["sudo", "foremost", "-i", path, "-o", "recovered_files"], 
                              capture_output=True, text=True)
        print("File recovery completed")
    except:
        print("File recovery failed")

def extract_metadata(filename):
    print(f"Extracting metadata from {filename}")
    
    if not os.path.exists(filename):
        print("File not found")
        return
    
    file_type = magic.from_file(filename)
    print(f"File type: {file_type}")
    
    file_size = os.path.getsize(filename)
    print(f"File size: {file_size} bytes")
    
    mod_time = os.path.getmtime(filename)
    print(f"Modified: {datetime.fromtimestamp(mod_time)}")
    
    with open(filename, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"SHA256: {file_hash}")
    
    if filename.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff')):
        with open(filename, 'rb') as f:
            tags = exifread.process_file(f)
            for tag, value in tags.items():
                if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                    print(f"{tag}: {value}")