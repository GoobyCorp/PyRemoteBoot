import os
import hashlib
import requests

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

class Client(object):
    session = None
    password = None

    def __init__(self, password):
        self.password = password
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

    def _auth_command(self, endpoint, args = None):
        response = self.session.get(self._build_url(ENDPOINT_CHALLENGE))
        if response.status_code == 200:  #valid request
            response_json = response.json()
            if response_json.has_key("challenge") and response_json.has_key("sequence"):
                sequence = int(response_json["sequence"])
                server_chal = response_json["challenge"]
                if len(server_chal) == 64:  #32 bytes = 64 hex chars
                    client_chal = self._gen_client_chal()
                    computed_chal = self._calc_sha_256(server_chal + client_chal + self._calc_sha_256(self.password))
                    get_data = {"r": computed_chal, "rs": sequence, "c": client_chal}
                    if args is not None and isinstance(args, dict):
                        get_data.update(args)
                    response = self.session.get(self._build_url(endpoint), params=get_data)
                    if response.status_code == 200: #valid challenge submission
                        response_json = response.json()
                        if response_json.has_key("r"):  #valid server challenge string received
                            server_r = response_json["r"]
                            if server_r == self._calc_sha_256(client_chal + server_chal + self._calc_sha_256(self.password)):  #server responded correctly
                                del(response_json["r"])  #remove server challenge response from the response as we don't need it anymore
                                self._set_session()  #reset session to remove anything cached in it
                                return {"success": True, "data": response_json}
        return {"success": False}

    def _set_session(self):
        if self.session is not None:
            self.session.close()
        self.session = requests.session()
        self.session.headers["User-Agent"] = USER_AGENT

    def _calc_sha_256(self, s):
        return hashlib.sha256(s).hexdigest()

    def _gen_client_chal(self):
        return os.urandom(32).encode("hex")  #random byte string encoded as hex of 64 chars length

    def _build_url(self, endpoint):
        return API_HOST + endpoint