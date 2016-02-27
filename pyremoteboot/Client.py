import os
import json
import hashlib
import requests

from Crypto.Cipher import AES

#known endpoints
ENDPOINT_CHALLENGE = "api/auth/challenge.php"
ENDPOINT_BUTTON = "api/button/press.php"
ENDPOINT_LED = "api/led/state.php"

#user agent for identifying what's making the request
USER_AGENT = "PyRemoteBoot v2.0"

#button id's
BUTTON_POWER = 0
BUTTON_RESET = 1

class Utils(object):
    @staticmethod
    def sha_256(s):
        return hashlib.sha256(s).hexdigest()

    @staticmethod
    def gen_client_chal(l = 32):
        return os.urandom(l).encode("hex")

class Crypt(object):
    def __init__(self, key, iv):
        if len(key) == 32 and len(iv) == 16:
            self.key = Utils.sha_256(key)
            self.iv = iv
        else:
            raise Exception("Key should be 32 bytes and iv should be 16 bytes.")

    def encrypt(self, s):
        bs = 16
        pad_count = bs - len(s) % bs
        pad = lambda s: s + pad_count * chr(pad_count)  #PCKS#7 padding
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        return cipher.encrypt(pad(s))

class Client(object):
    host = None
    session = None
    password = None

    def __init__(self, host, password):
        self.host = "http://" + host + "/"
        self.password = Utils.sha_256(password)  #hashed immediately
        self._set_session()

    def press_button(self, button_id, time):
        if isinstance(button_id, int) and isinstance(time, int):
            return self._auth_command(ENDPOINT_BUTTON, {"button_id": button_id, "time": time})
        return {"success": False}

    def read_leds(self):
        return self._unauth_command(ENDPOINT_LED)

    def _unauth_command(self, endpoint):
        response = self.session.get(self._build_url(endpoint))
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        return {"success": False}

    def _auth_command(self, endpoint, json_payload = None):
        response = self.session.get(self._build_url(ENDPOINT_CHALLENGE))
        if response.status_code == 200:  #valid request
            response_json = response.json()
            if response_json.has_key("challenge") and response_json.has_key("sequence"):
                sequence = int(response_json["sequence"])
                server_chal = response_json["challenge"]
                if len(server_chal) == 64:  #hex-encoded
                    client_chal = Utils.gen_client_chal()
                    computed_chal = Utils.sha_256(server_chal + client_chal + self.password)
                    get_data = {"r": computed_chal, "rs": sequence, "c": client_chal}
                    if isinstance(json_payload, dict):
                        json_payload_str = json.dumps(json_payload)
                        cipher = Crypt(self.password.decode("hex"), server_chal[:32].decode("hex"))  #raw sha256'd password (32) and raw server challenge (16)
                        payload = cipher.encrypt(json_payload_str)
                        get_data["l"] = len(payload)
                        get_data["p"] = payload
                    response = self.session.get(self._build_url(endpoint), params=get_data)
                    if response.status_code == 200:
                        response_json = response.json()
                        if response_json.has_key("r"):
                            server_r = response_json["r"]
                            if server_r == Utils.sha_256(client_chal + server_chal + self.password):  #server responded correctly
                                del(response_json["r"])
                                self._set_session()
                                return {"success": True, "data": response_json}
        return {"success": False}

    def _set_session(self):
        if self.session is not None:
            self.session.close()
        self.session = requests.session()
        self.session.headers["User-Agent"] = USER_AGENT

    def _build_url(self, endpoint):
        return self.host + endpoint