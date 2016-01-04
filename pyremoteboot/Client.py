import os
import string
import hashlib
import requests

#this will change when I actually know it
API_HOST = "https://www.example.com/"

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
        if self.password:
            self.password = password
            self._set_session()

    def press_button(self, button_id, time):
        return self.send_command(ENDPOINT_BUTTON, {"button_id": button_id, "time": time})

    def read_leds(self):
        response = self.session.get(ENDPOINT_LED)
        if response.status_code == 200:  #valid response
            return {"success": True, "data": response.json()}
        return {"success": False}

    def send_command(self, endpoint, args = None):
        response = self.session.get(self._build_url(ENDPOINT_CHALLENGE))
        if response.status_code == 200:  #valid request
            response_json = response.json()
            if response_json.has_key("challenge") and response_json.has_key("sequence"):
                sequence = int(response_json["sequence"])
                server_chal = response_json["challenge"]
                client_chal = self._gen_client_chal()
                computed_chal = self._calc_sha_256(server_chal + client_chal + self._calc_sha_256(self.password))

                get_data = {"r": computed_chal, "rs": sequence, "c": client_chal}
                if args is not None and isinstance(args, dict):
                    get_data.update(args)

                response = self.session.get(self._build_url(endpoint), get_data)

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
        return os.urandom(64)  #random byte string of 64 chars length

    def _build_url(self, endpoint):
        return API_HOST + endpoint
