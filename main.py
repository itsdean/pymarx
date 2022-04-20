import argparse
import zipfile

from lib.Checkmarx import Checkmarx
from lib.constants import *

def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--host",
        help = "The URL of the Checkmarx instance to connect to"
    )

    parser.add_argument(
        "--username",
        help = "The username to authenticate to Checkmarx with"
    )

    parser.add_argument(
        "--password",
        help = "The password to authenticate to Checkmarx with"
    )

    parser.add_argument(
        "--project-file",
        help = "The name of the .zip file containing the project code"
    )

    parser.add_argument(
        "--project-name",
        help = "The name of the associated project in Checkmarx"
    )
    
    parser.add_argument(
        "--team",
        help = "The team that owns the project"
    )

    parser.add_argument(
        "--comment",
        default = "",
        help = "A comment to be left with the scan"
    )

    parser.add_argument(
        "--no-wait",
        default = False,
        action = "store_true",
        help = "Forces the script to not wait for and track results of the scan"
    )

    parser.add_argument(
        "--report",
        default = "checkmarx-report",
        help = "The name of the file the report should be saved to."
    )

    parser.add_argument(
        "--report-filetype",
        default = "csv",
        choices = [
            "csv"
        ],
        help = "The extension that Checkmarx should export the report as"
    )

    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_arguments()

    # Check that the file provided is a zip file
    if not zipfile.is_zipfile(arguments.project_file):
        exit(INVALID_ZIP_FILE)

    cx = Checkmarx(arguments)
    cx.scan()

    # If we waited for the scan results and it finished, download the report
    if not arguments.no_wait:
        cx.get_report()

    print()
