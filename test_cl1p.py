import src.secrets as secret_cfg
import requests
import concurrent.futures

token = secret_cfg.CL1P_API_TOKEN
url = "https://api.cl1p.net/test1234"

def fetch(i):
    try:
        r = requests.get(url, headers={'cl1papitoken': token}, timeout=3)
        return r.status_code
    except Exception as e:
        return str(e)

with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    results = list(executor.map(fetch, range(100)))

from collections import Counter
print(Counter(results))
