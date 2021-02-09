from requests_toolbelt import MultipartEncoder
import datetime
import dateutil.parser
import json
import requests
import time

REST_API_PATH = "/cxrestapi"
AUTH_API_PATH = REST_API_PATH + "/auth/identity/connect/token"
PROJECTS_API_PATH = REST_API_PATH + "/projects"
SCAN_API_PATH = REST_API_PATH + "/sast/scans"
TEAMS_API_PATH = REST_API_PATH + "/auth/teams"


class Checkmarx:


    def __fail(self, response):
        print("\n")
        print("Response Status Code: " + str(response.status_code))
        print("--- Start of Response Body ---")
        print(response.text)
        print("--- End of Response Body ---")
        print("\n")


    def __check_host_validity(self):
        try:        
            response = requests.get(
                self.host,
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
            self.host + AUTH_API_PATH,
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
            print("> Authenticated to API")
            self.cookies = response.cookies
            return json.loads(response.text)["access_token"]

        else:
            print("> Could not authenticate!")
            self.__fail(response)
            exit(-2)


    def __init__(self, args):

        print()

        self.is_public = True
        self.wait = True

        self.a = args

        if args.no_wait:
            self.wait = False

        # todo: existence logic
        self.project_file = self.a.project_file
        self.project_name = self.a.project_name
        self.team_name = self.a.team

        self.comment = self.a.comment

        # Check that the host is accessible
        self.host = self.a.host
        self.__check_host_validity()

        self.username = self.a.username
        self.password = self.a.password

        # Try to log in
        self.access_token = self.__authenticate()
        self.headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json",
            "Accept": "application/json;v=1.0"
        }


    def __get_projects(self):
        response = requests.get(
            self.host + PROJECTS_API_PATH,
            headers = self.headers,
            cookies = self.cookies,
            verify = True,
            stream = True
        )

        if response.status_code == 200:
            return json.loads(response.text)
        else:
            print("There was an error retrieving projects.")
            self.__fail(response)
            exit(-3)


    def __get_project(self):
        print("\nSearching for an existing project")
        projects = self.__get_projects()

        for project in projects:
            if project["name"] == self.project_name:
                print("> An existing project was found!")
                return project
        return None


    def __get_teams(self):
        response = requests.get(
            self.host + TEAMS_API_PATH,
            headers = self.headers,
            cookies = self.cookies,
            verify = True,
            stream = True
        )

        if response.status_code == 200:
            return json.loads(response.text)
        else:
            print("There was an error retrieving teams.")
            print(response.status_code)
            print(response.text)
            exit(-4)


    def __get_team(self):
        teams = self.__get_teams()

        for team in teams:
            if "fullName" in team:
                if self.team_name in team["fullName"]:
                    return team["id"]
        return None


    def __create_project(self):
        print("> No existing project was found - creating one!")

        team_id = self.__get_team()
        if team_id is not None:

            data = json.dumps(
                {
                    "name": self.project_name,
                    "owningTeam": team_id,
                    "isPublic": self.is_public
                }
            )

            # Create the project
            response = requests.post(
                self.host + PROJECTS_API_PATH,
                headers = self.headers,
                data = data,
                cookies = self.cookies,
                verify = True,
                stream = True
            )

            if response.status_code == 201:
                return json.loads(response.text)
            else:
                print("There was an error creating a project.")
                print(response.status_code)
                print(response.text)
                exit(-5)  


    def __upload_project_file(self):
        print("\nUploading " + self.project_file + "...")

        # Get only the filename in case a path is provided 
        project_file_name = self.project_file
        if "/" in self.project_file:
            project_file_name = self.project_file.split("/")[-1]

        # Split the zip via multipart
        mpe = MultipartEncoder(
            fields = {
                "zippedSource": (
                    project_file_name,
                    open(self.project_file, "rb"),
                    "application/zip"
                )
            }
        )

        upload_api_path = PROJECTS_API_PATH \
                            + "/" + str(self.project_id) \
                            + "/sourceCode/attachments"

        response = requests.post(
            self.host + upload_api_path,
            headers = {
                "Authorization": "Bearer " + self.access_token,
                "Content-Type": mpe.content_type
            },
            data = mpe,
            cookies = self.cookies,
            verify = True,
            stream = True
        )

        if response.status_code == 204:
            print("> Project file uploaded!")
        else:
            print("There was an error uploading the project file to Checkmarx.")
            self.__fail(response)
            exit(-6)


    def __check_scan(self):

        status = ""

        # scan_url = self.host + SCAN_API_PATH + "/" + self.scan_id
        scan_url = self.host + REST_API_PATH + self.scan_url

        response = requests.get(
            scan_url,
            headers = self.headers,
            cookies = self.cookies,
            verify = True,
            stream = True
        )

        if response.status_code == 200:
            return json.loads(response.text)

        else:
            print("There was an error retrieving the status of the scan.")
            self.__fail(response)
            exit(-8)


    def scan(self):
        is_incremental = True
        force_scan = True

        project = self.__get_project()

        if project is None:
            project = self.__create_project()

        self.project_id = project["id"]
        print("> Project ID: " + str(self.project_id))

        self.__upload_project_file()
        print("\nStarting scan")

        data = json.dumps(
            {
                "projectId": self.project_id,
                "isIncremental": is_incremental,
                "forceScan": force_scan,
                "comment": self.comment
            }
        )

        response = requests.post(
            self.host + SCAN_API_PATH,
            headers = self.headers,
            data = data,
            cookies = self.cookies,
            verify = True,
            stream = True
        )

        if response.status_code == 201:
            self.scan_id = json.loads(response.text)["id"]
            self.scan_url = json.loads(response.text)["link"]["uri"]
        else:
            print("> There was an error starting the scan.")
            self.__fail(response)
            exit(-7)

        status = ""
        started = False
        start_time = None
        counter = 0

        sleep_duration = 5

        while status != "Finished":
            scan_information = self.__check_scan()
            # On the first instance of getting scan information, output some start info
            if not started:
                start_time = dateutil.parser.parse(
                    scan_information["dateAndTime"]["startedOn"]
                )
                print("> Scan started at " + str(start_time.date()) + " " + str(start_time.time()))
                started = True

                # If we don't want to wait, break and stop here.
                if not self.wait:
                    break

            else:
                counter += sleep_duration
                status = scan_information["status"]["name"]
                stage = scan_information["status"]["details"]["stage"]
                step = scan_information["status"]["details"]["step"]

                print("> Time elapsed: " + str(counter) + " seconds - " \
                        + status \
                        + " - " + stage)

            time.sleep(sleep_duration)

        if status == "Finished":
            print("\nScan complete!")
        print()
