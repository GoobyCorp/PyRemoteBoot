import os
import json
import hashlib
import requests

from Crypto.Cipher import AES

#Local IP of RemoteBoot device
API_HOST = "http://192.168.1.108/"

#known endpoints
ENDPOINT_CHALLENGE = "api/auth/challenge.php"
ENDPOINT_BUTTON = "api/button/press.php"
ENDPOINT_LED = "api/led/state.php"

#user agent for identifying what's making the request
USER_AGENT = "PyRemoteBoot v1.0"

#button id's
BUTTON_POWER = 0
BUTTON_RESET = 1

class Utils(object):
    @staticmethod
    def is_valid_json(s):
        try:
            json.loads(s)
            return True
        except:
            return False

    @staticmethod
    def sha_256(s):
        return hashlib.sha256(s).hexdigest()

    @staticmethod
    def gen_client_chal(l = 32):
        client_chal = os.urandom(l).encode("hex")
        return client_chal

class Crypt(object):
    def __init__(self, key, iv):
        self.bs = 32
        if key and iv:
            self.key = Utils.sha_256(key)
            self.iv = iv

    def encrypt(self, s):
        pad = lambda s: s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        return cipher.encrypt(pad(s))

    def decrypt(self, s):
        unpad = lambda s : s[:-ord(s[len(s)-1:])]
        cipher = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        return unpad(cipher.decrypt(s))

class Client(object):
    session = None
    password = None

    def __init__(self, password):
        self.password = Utils.sha_256(password)  #hashed immediately
        self._set_session()

    def press_button(self, button_id, time):
        if isinstance(button_id, int) and isinstance(time, int):
            return self._auth_command(ENDPOINT_BUTTON, json.dumps({"button_id": button_id, "time": time}))
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
                if len(server_chal) == 64:  #32 bytes = 64 hex chars
                    client_chal = Utils.gen_client_chal()
                    computed_chal = Utils.sha_256(server_chal + client_chal + self.password)
                    get_data = {"r": computed_chal, "rs": sequence, "c": client_chal}
                    if isinstance(json_payload, str) and Utils.is_valid_json(json_payload):
                        cipher = Crypt(self.password, client_chal.decode("hex"))  #sha256 password = key and client_chal = non-hex client challenge
                        payload = cipher.encrypt(json_payload)
                        get_data["l"] = len(payload)
                        get_data["p"] = payload
                    response = self.session.get(self._build_url(endpoint), params=get_data)
                    if response.status_code == 200: #valid challenge submission
                        response_json = response.json()
                        if response_json.has_key("r"):  #valid server challenge string received
                            server_r = response_json["r"]
                            if server_r == Utils.sha_256(client_chal + server_chal + self.password):  #server responded correctly
                                del(response_json["r"])  #remove server challenge response from the response as we don't need it anymore
                                self._set_session()  #reset session to remove anything cached in it
                                return {"success": True, "data": response_json}
        return {"success": False}

    def _set_session(self):
        if self.session is not None:
            self.session.close()
        self.session = requests.session()
        self.session.headers["User-Agent"] = USER_AGENT

    def _build_url(self, endpoint):
        return API_HOST + endpoint