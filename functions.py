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
    session.proxies = {'http': 'socks5://127.0.0.1:9050',
                       'https': 'socks5://127.0.0.1:9050'}
    return session


def handle_request(name: str, payload: str, function) -> dict:
    from constants import api, config
    try:
        if api.session.proxies == {}:
            response = function(config["server_address"] + "/api/" + name, json=payload, verify=False, timeout=5)
        else:
            response = function(config["server_address"] + "/api/" + name, json=payload, verify=False)
        if name != "get_file":
            return response.json()
        return response.content
    except requests.exceptions.ConnectionError as e:
        return {"status": "error", "error": "No internet connection"}
    except Exception as e:
        return {"error": str(e), "status": "error"}
