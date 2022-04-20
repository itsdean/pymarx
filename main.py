import argparse

from lib.Checkmarx import Checkmarx


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-u",
        "--url",
        help = "The URL of the Checkmarx instance to connect to"
    )

    arguments = parser.parse_args()

    return arguments


if __name__ == "__main__":
    arguments = parse_arguments()
    cx = Checkmarx(arguments)
