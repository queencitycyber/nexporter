import os
import subprocess

from sh import sqlitebiter


class Sqlserve:
    def __init__(self, output) -> None:

        # Get list of csv files from output directory
        csv_files = [file for file in os.listdir(output) if file.endswith(".csv")]

        self.file_list = []
        for file in csv_files:
            self.file_list.append(os.path.join(output, file))
        

    def convert(self):
        """Convert all csv files to sql files"""
        # Convert list of csv files to string

        # Craft sqlitebiter command
        command =  ["sqlitebiter", "-o", "output.sql", "file"]
        for file in self.file_list:
            command.append(f'{file}')

        print(command)
        subprocess.run(command)

    def serve(self):
        """Serve sql file"""

        # Serve sql file using datasette
        subprocess.run(["datasette", "serve", "output.sql"])
