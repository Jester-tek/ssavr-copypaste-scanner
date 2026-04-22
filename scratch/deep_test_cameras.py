
import requests
import concurrent.futures

def test_ip(ip_port):
    results = {}
    base_url = f"http://{ip_port}"
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1",
        "Panasonic-Network-Camera"
    ]
    
    paths = ["/", "/anony/mjpg.cgi", "/SnapshotJPEG", "/mjpg/video.mjpg"]
    
    for path in paths:
        url = base_url + path
        for ua in user_agents:
            try:
                # 5 second timeout
                resp = requests.get(url, headers={"User-Agent": ua}, timeout=5, stream=True)
                status = resp.status_code
                # Check first 100 bytes to see if it's an MJPG stream
                content_preview = ""
                if status == 200:
                    content_preview = resp.raw.read(100).hex()
                
                results[f"{path} | {ua[:15]}"] = f"{status} | {content_preview[:20]}..."
                resp.close()
                if status == 200:
                    break # Found something
            except Exception as e:
                results[f"{path} | {ua[:15]}"] = str(e)
    return ip_port, results

def main():
    # Targets that didn't timeout or had interesting status
    targets = [
        "201.248.21.187:80",
        "188.187.190.160:80",
        "82.209.67.201:80",
        "195.14.173.10:80",
        "77.37.152.175:80",
        "84.32.72.78:80",
        "62.141.90.14:80",
        "190.15.193.47:80"
    ]
    
    print("Starting deep test on interesting IPs...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_ip = {executor.submit(test_ip, ip): ip for ip in targets}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip, res = future.result()
            print(f"\n--- Results for {ip} ---")
            for k, v in res.items():
                if "200" in v or "401" in v or "403" in v:
                    print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
