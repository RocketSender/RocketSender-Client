import requests


def password_check(passwd):
    val = True
    err_text = None

    if len(passwd) < 8:
        err_text = 'length should be at least 8'
        val = False

    if not any(char.isdigit() for char in passwd):
        err_text = 'Password should have at least one numeral'
        val = False

    if not any(char.isupper() for char in passwd):
        err_text = 'Password should have at least one uppercase letter'
        val = False

    if not any(char.islower() for char in passwd):
        err_text = 'Password should have at least one lowercase letter'
        val = False

    return val, err_text


def get_tor_session():
    session = requests.Session()
    # Tor uses the 9050 port as the default socks port
    session.proxies = {'http': 'socks5://127.0.0.1:9050',
                       'https': 'socks5://127.0.0.1:9050'}
    return session


def handle_request(name: str, payload: str, function) -> dict:
    from constants import LINK
    try:
        response = function(LINK + "/api/" + name, json=payload, verify=False)
        return response.json()
    except requests.exceptions.ConnectionError as e:
        return {"status": "error", "error": "No internet connection"}
    except Exception as e:
        return {"error": str(e), "status": "error"}
