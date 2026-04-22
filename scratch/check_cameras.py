
import re
import requests
import concurrent.futures

def extract_urls(file_path):
    urls = []
    found_target = False
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if 'justpaste.it/imec' in line:
                found_target = True
                continue
            
            if found_target:
                if line.startswith('==='):
                    found_target = False
                    continue
                if line.startswith('http'):
                    match = re.search(r'(http[^\s]+)', line)
                    if match:
                        urls.append(match.group(1))
    return list(set(urls))

def check_url(url):
    try:
        # Use a short timeout to check if the server responds
        response = requests.head(url, timeout=3)
        return url, response.status_code
    except Exception as e:
        return url, str(e)

def main():
    file_path = '/home/versus/Scrivania/ssavr-copypaste-scanner/justpaste_clean.txt'
    
    print(f"Extracting URLs from {file_path}...")
    urls = extract_urls(file_path)
    print(f"Found {len(urls)} unique URLs.")
    
    if not urls:
        print("No URLs found.")
        return
    
    print("Checking status of URLs...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(check_url, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url, status = future.result()
            results.append((url, status))
            if isinstance(status, int) and status == 200:
                print(f"[LIVE] {url}")
            # else:
            #     print(f"[DEAD] {url} - {status}")

    # Save results
    with open('camera_urls_status.txt', 'w') as f:
        for url, status in results:
            f.write(f"{url} | {status}\n")
    
    live_count = sum(1 for _, s in results if isinstance(s, int) and s == 200)
    print(f"\nSummary: {live_count} live URLs out of {len(urls)} found.")

if __name__ == "__main__":
    main()
