# pymarx

## Sample Usage
```shell
./main.py --host <checkmarx_host> --username <checkmarx_username> --password <checkmarx_password> --project-file <project_zip> --project-name <<project_name>> --team <<project_team>> 
```

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
