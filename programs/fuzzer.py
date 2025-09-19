import requests
import concurrent.futures

def http_fuzzer(url, wordlist):
    print(f"Fuzzing URL: {url}")
    
    def fuzz_path(path):
        try:
            test_url = f"{url}/{path}"
            response = requests.get(test_url, timeout=5)
            if response.status_code < 400:
                print(f"Found: {test_url} ({response.status_code})")
        except:
            pass
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(fuzz_path, wordlist)