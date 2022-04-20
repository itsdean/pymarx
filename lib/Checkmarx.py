import requests

REST_API_PATH = "/cxrestapi"
AUTH_API_PATH = REST_API_PATH + "/auth/identity/connect/token"

class Checkmarx:


    def __check_validity(self, url):
        try:        
            response = requests.get(
                url,
                timeout=5
            )
            if response.status_code == 200:
                return True

        except requests.Timeout:
            print("Timed out connecting to the URL.")
            print("Please check it is accessible from where you are.")
            exit(-1)

        return False


    def __init__(self, args):
        self.a = args

        url = self.a.url
        if self.__check_validity(url):
            print("Checkmarx API is accessible")
        self.api_url = url + REST_API_PATH
