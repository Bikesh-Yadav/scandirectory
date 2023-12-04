import os
import hashlib
import requests
import json

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
VIRUSTOTAL_API_KEY = 'your_api_key_here'
def calculate_hash(file_path):
    # Calculate MD5 hash of the file
    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def scan_directory(directory_path):
    suspicious_patterns = ['.exe', '.vbs', '.ps1', '.bat', '.cmd'] #you can use any extension here
    malicious_files = []

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if any(file.lower().endswith(pattern) for pattern in suspicious_patterns):
                file_path = os.path.join(root, file)
                malicious_files.append(file_path)

    return malicious_files

def check_file_reputation(file_path):
    md5_hash = calculate_hash(file_path)

    url = f'https://www.virustotal.com/api/v3/files/{md5_hash}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return None

def save_results(malicious_files):
    output_folder = 'malicious_files_output'
    os.makedirs(output_folder, exist_ok=True)

    for file_path in malicious_files:
        result = check_file_reputation(file_path)
        if result and result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
            print(f'Malicious file detected: {file_path}')
            output_file_path = os.path.join(output_folder, f'{os.path.basename(file_path)}_output.txt')
            with open(output_file_path, 'w') as output_file:
                output_file.write(json.dumps(result, indent=2))
            print(f'Results saved to: {output_file_path}')

if __name__ == '__main__':
    directory_to_scan = r'folder_location_here'  # Use raw string to avoid escape characters
    malicious_files = scan_directory(directory_to_scan)

    if malicious_files:
        save_results(malicious_files)
