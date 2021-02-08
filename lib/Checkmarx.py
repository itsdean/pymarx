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
                print("Checkmarx API is accessible")
                return True

        except requests.Timeout:
            print("Timed out connecting to the URL.")
            print("Please check it is accessible from where you are.")
            exit(-1)

        return False


    def __authenticate(self):
        response = requests.post(
            AUTH_API_PATH,
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data = {
                "username": self.username,
                "password": self.password,
                "grant_type": "password",
                "scope": "sast_rest_api",
                "client_id": "resource_owner_client",
                "client_secret": "014DF517-39D1-4453-B7B3-9930C563627C"
            }
        )

        if response.status_code == 200:
            print("Authenticated to API")


    def __init__(self, args):
        self.a = args

        url = self.a.url
        self.api_url = url + REST_API_PATH

        self.username = self.a.username
        self.password = self.a.password

        # Check that the URL is accessible
        self.__check_validity(url)
            
        # Try to log in
        client = self.__authenticate()
