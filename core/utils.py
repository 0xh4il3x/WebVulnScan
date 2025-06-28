import requests

def is_target_alive(url, timeout=10):
    try:
        response = requests.get(url, timeout=timeout)
        return True
    except requests.exceptions.RequestException:
        return False