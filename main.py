import argparse

from lib.Checkmarx import Checkmarx


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--url",
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

    arguments = parser.parse_args()

    return arguments


if __name__ == "__main__":
    arguments = parse_arguments()
    cx = Checkmarx(arguments)
