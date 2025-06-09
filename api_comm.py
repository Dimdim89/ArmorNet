import json
import requests
from pathlib import Path

file_path = Path("sniffed_data.json")

def send_data_to_api():
    if file_path.exists():
        with file_path.open("r") as f:
            data = json.load(f)

            response = requests.post (
                "enter address here",
                json=data
            )
            print(f"Status code: {response.status_code}")
            print(f"Response: {response.text}")
    else:
        print("File does not exist.")