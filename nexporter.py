import json
import logging
import os
from datetime import datetime

import requests
import rich_click as click
from rich.table import Table

from rich.progress import track
from rich.console import Console
from rich.logging import RichHandler

from sqlserve import Sqlserve

FORMAT = "%(message)s"
logging.basicConfig(level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=True)])
log = logging.getLogger("rich")
console = Console()

print = print

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_ERRORS_SUGGESTION = "magenta italic"
click.rich_click.ERRORS_SUGGESTION = "Try running the '--help' flag for more information."


@click.command()
@click.option("--target", "-t", required=True, default="https://127.0.0.1:8834", show_default=True, help="The URL of the Nessus Server.")
@click.option('--username', '-u', required=True, envvar="NESSUS_USER", help="The username to use for authentication.")
@click.option('--password', '-p', prompt=True, hide_input=True,required=True, envvar="NESSUS_PASS", help="The password to use for authentication.")
@click.option("--output",'-od', type=click.Path(resolve_path=True, file_okay=False), required=False, default="scans",show_default=True, help="Output directory to store scans.")
@click.option('--serve', '-s', is_flag=True, help="Exposes DataSette for exploration.")
@click.option("--debug/--no-debug", "-d/-nd", default=False, show_default=True, help="Enable debug mode.")
@click.option("--verbose/--no-verbose", "-v/-nv", default=False, show_default=True, help="Enable verbose mode.")
@click.version_option(version='0.0.1', prog_name='nexporter')
def cli(target, username, password, output, serve, debug, verbose):
    """
    Export & Explore Nessus Professional Scan Data (NEXPORTER) \n
    Run the --serve option to view data. Exposed on http://localhost:8001/ \n
    """

    def authenticate():
        login_url = f'{target}' + '/session'   
        resp = requests.post(login_url, data={'username': {username}, 'password': {password}}, verify=False)
        token = json.loads(resp.text)             
        
        if verbose:
            print('Verbose output enabled')
            print('Token: {}'.format(token['token']))
        if debug:
            print('Debug output enabled')
            print('URL: {}'.format(login_url))
            print('Username: {}'.format(username))
            print('Token: {}'.format(token['token']))

        if resp.status_code == 200:
            token={'X-Cookie': 'token=' + token['token']}
            print('Authentication successful')
            return token
            
        else:
            print('Authentication failed')
            print('Status code: {}'.format(resp.status_code))
            print('Response: {}'.format(resp.text))
            exit()
    token = authenticate() 

    def create_directory():
        if not os.path.exists(output):
            os.makedirs(output)
            if verbose:
                print('Created directory: {}'.format(output))
    create_directory()

    def list_scans():
        target_url = f"{target}" + "/scans"
        resp = requests.get(target_url, headers=token, verify=False)
        scans = resp.json()["scans"]
        if verbose:
            print('Scans: {}'.format(scans))
        else:
            pass
        return scans

    def get_scans(scan):
        print("Hang tight - getting scans now...")
        scan_id = scan["id"]
        target_url = f"{target}" + f"/scans/{scan_id}" 
        try:
            resp = requests.get(target_url, headers=token, verify=False, timeout=2)
            scan_details = {
                "id": scan_id,
                "name": scan["name"],
                "status": resp.json()["info"]["status"],
            }

            return scan_details
        except requests.exceptions.Timeout:
            pass

    def download_scans(scans):
        for scan in scans:
            if scan is not None:
                if scan["status"] == "completed":
                    export_attempts = 0
                    scan_id = scan["id"]
                    scan_name = scan["name"]
                    target_url = f"{target}" + f"/scans/{scan_id}/export"
                    export_resp = requests.post(target_url, headers=token, json={"format": "csv"}, verify=False).json()
                    while True:
                        target_url = f"{target}/tokens/{export_resp['token']}/status"

                        status_resp = requests.get(target_url, headers=token, verify=False)

                        if status_resp.json()["status"] == "ready":
                            print(f"Scan {scan_name} ready for download")
                            target_url = f"{target}/tokens/{export_resp['token']}/download"
                            export_file_name = scan_name + "_" + str(datetime.now().strftime("%d%m%Y")) + ".csv"
                            export_file_name = export_file_name.replace(" ", "_")
                            export_file_path = os.path.join(output, export_file_name)
                            downloaded_scan = requests.get(target_url, headers=token, verify=False)
                            with open(export_file_path, "wb") as f:
                                f.write(downloaded_scan.content)
                            break
                        else:
                            print(status_resp)
                            export_attempts += 1

                        if export_attempts > 5:
                            print(f"Scan {scan_name} failed to export after 5 attempts, skipping")
                            break
    
    scans = list_scans()
    scan_details = [get_scans(scan) for scan in scans]
    download_scans(scan_details)    

    if serve:
        sqlserve = Sqlserve(output)
        sqlserve.convert()
        sqlserve.serve()



if __name__ == "__main__":
  try:
    cli()

  except Exception as e:
    console.print_exception(show_locals=True)
