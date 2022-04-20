from zipfile import error
from requests_toolbelt import MultipartEncoder
import csv
import dateutil.parser
import io
import json
import os
import requests
import time

from lib.constants import *

REST_API_PATH = "/cxrestapi"
AUTH_API_PATH = REST_API_PATH + "/auth/identity/connect/token"
PROJECTS_API_PATH = REST_API_PATH + "/projects"
RESULTS_API_PATH = REST_API_PATH + "/reports/sastScan"
SCAN_API_PATH = REST_API_PATH + "/sast/scans"
TEAMS_API_PATH = REST_API_PATH + "/auth/teams"


class Checkmarx:


    def __fail(self, response, error_code):
        print("\n")
        print("Response Status Code: " + str(response.status_code))
        print("--- Start of Response Body ---")
        print(response.text)
        print("--- End of Response Body ---")
        print("\n")
        exit(error_code)


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
            exit(HOST_TIMEOUT)

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
            self.__fail(response, AUTHENTICATION_FAILURE)


    def __init__(self, args):

        print()

        self.is_public = True
        self.wait = True

        self.a = args

        self.report_path = self.a.report
        self.report_filetype = self.a.report_filetype

        if args.no_wait:
            self.wait = False

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
            self.__fail(response, PROJECT_RETRIEVAL_FAILURE)


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
            self.__fail(response, TEAM_RETRIEVAL_FAILURE)


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
                self.__fail(response, PROJECT_CREATION_FAILURE)


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
            self.__fail(response, PROJECT_FILE_UPLOAD_FAILURE)


    def __check_scan(self):

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
            self.__fail(response, SCAN_STATUS_RETRIEVAL_FAILURE)


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
            self.__fail(response, SCAN_START_FAILURE)

        started = False

        counter = 0
        sleep_duration = 5

        while True:
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

                message = "> Time elapsed: " \
                            + str(counter)  + "s - " \
                            + status

                if stage != "":
                    message += " - " + stage

                print(message)

                if status == "Finished":
                    print("Scan complete!\n")
                    break
                elif "No code changes were detected" in stage:
                    print("There we no code changes since the last scan!\n")
                    break

            time.sleep(sleep_duration)


    def get_report(self):

        print("Retrieving scan results...")

        data = json.dumps(
            {
                "scanId": self.scan_id,
                "reportType": self.report_filetype
            }
        )

        response = requests.post(
            self.host + RESULTS_API_PATH,
            headers = self.headers,
            data = data,
            cookies = self.cookies,
            verify = True,
            stream = True
        )

        if response.status_code != 202:
            print("There was an issue obtaining the scan results.")
            self.__fail(response, REPORT_STATUS_RETRIEVAL_FAILURE)

        report_url = json.loads(response.text)["links"]["report"]["uri"]
        status_url = json.loads(response.text)["links"]["status"]["uri"]

        value = "InProcess"

        # Poll the API until the report has been created
        while value != "Created":
            response = requests.get(
                self.host + REST_API_PATH + status_url,
                headers = self.headers,
                cookies = self.cookies,
                verify = True,
                stream = True
            )
            value = json.loads(response.text)["status"]["value"]
            time.sleep(5)

        response = requests.get(
            self.host + REST_API_PATH + report_url,
            headers = self.headers,
            cookies = self.cookies,
            verify = True,
            stream = True
        )

        json_object = {
            "results": []
        }

        io_buffer = io.StringIO(response.text)
        reader = csv.DictReader(io_buffer)

        for row in reader:
            json_object["results"].append(
                json.loads(json.dumps(row))
            )

        report_path = os.path.abspath(self.report_path)
        full_report_path = report_path + ".json"

        with open (full_report_path, "w") as report_file_object:
            json.dump(json_object, report_file_object)

        print("> Report saved to " + full_report_path + "!")
