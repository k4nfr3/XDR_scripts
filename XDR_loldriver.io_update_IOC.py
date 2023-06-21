import requests
import xml.etree.ElementTree as ET
import pandas as pd

from datetime import datetime, timezone
import secrets
import string
import hashlib
import json
import math

def download_xml_content(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.content
    else:
        print("Failed to download XML content from URL :" + str(url))
        return None


def log(message):
    log_file_path="log.txt"
    log_to_file = False
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_message = f"[{timestamp}] {message}"

    # Print the message with timestamp to the screen
    print(log_message)

    if log_to_file: # only if set to True above
        # Log the message to a file
        with open(log_file_path, "a") as log_file:
            log_file.write(log_message + "\n")

def extract_content(xml):
    root = ET.fromstring(xml)
    content_list = []
    for element in root.iter():
        if element.tag.startswith("Hashes"):
            mysplit= element.text.split("=")
            if len(mysplit) == 2:
                if (mysplit[0] == "MD5") or (mysplit[0] == "SHA256"):
                    content_list.append([mysplit[0], mysplit[1]])
    return content_list

def create_table(content_list):
    df = pd.DataFrame(content_list, columns=["Type", "Content"])
    return df


def upload_IOC_to_xdr(xdr_url, api_key_id, api_key, hashtable):
   # Generate a 64 bytes random string
    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
    # Get the current timestamp as milliseconds.
    timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000
    # Generate the auth key:
    auth_key = "%s%s%s" % (api_key, nonce, timestamp)
    # Convert to bytes object
    auth_key = auth_key.encode("utf-8")
    # Calculate sha256:
    api_key_hash = hashlib.sha256(auth_key).hexdigest()
    # Generate HTTP call headers
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-xdr-timestamp": str(timestamp),
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash
    }
    # Calculate the timestamp for 7 days
    seven_days_timestamp = int((datetime.now().timestamp() * 1000) + (7 * 24 * 60 * 60*1000))


    # Get the total number of rows in the table
    total_rows = len(hashtable)

    # Calculate the number of iterations required
    iterations = math.ceil(total_rows / 100)

    # Loop through the table in steps of 100
    for i in range(iterations):
        start_index = i * 100
        end_index = min((i + 1) * 100, total_rows)

        payload = {
            "request_data": [
            ],
            "validate": True
        }

        # Iterate over the rows within the current step
        mycount=0
        for index, row in table.iloc[start_index:end_index].iterrows():
            #log("Type: "+ row["Type"] + " Content: " + row["Content"])
            new_hash = {
                "indicator": row["Content"],
                "type": "HASH",
                "comment": "IOC from loldriver.IO",
                "reputation": "GOOD",
                "reliability": "C",
                "severity": "HIGH",
                "class": "Vulnerable Driver",
                "expiration_date": seven_days_timestamp
            }
            mycount+=1
            # Append the new member to the "request_data" list
            payload["request_data"].append(new_hash)

            # Convert the updated payload back to JSON
            #updated_payload = json.dumps(payload)

        res = requests.post(url="https://api-" + xdr_url + "/public_api/v1/indicators/insert_jsons",
                            headers=headers,
                            json=payload)
        if res.reason != "OK":
            log("ERROR posting content to XDR @ " + xdr_url)
            log(str(headers))
            log(str(payload))
            log(str(res))
            log(str(res.reason))
        else:
            data = json.loads(res.text)
            try:
                if data['reply']['success'] == True:
                    log("POST successfull of : " + str(mycount) + " Hashes")
                else:
                    log("Error" + str(data['reply']['validation_errors']))
                    log("Error got " + str(len(data['reply']['validation_errors']))+ " errors")
            except:
                log("Error in request but didn't get success status" + str(res.text))
    return res






# Press the green button in the gutter to run the script.
api_key_id = "xyz"
api_key = "***************************************"
XDR_fqdn = "<changeme>.xdr.eu.paloaltonetworks.com"

if __name__ == '__main__':
    # URL of the XML file
    xml_url = "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/detections/sysmon/sysmon_config_vulnerable_hashes_block.xml"

    # Download the XML content
    xml_content = download_xml_content(xml_url)

    if xml_content:
        # Extract the content from XML
        content_list = extract_content(xml_content)

        # Create a table with the extracted content
        table = create_table(content_list)
        log("Download successfull of : " + str(len(table)) + " Hashes")
        upload_IOC_to_xdr(XDR_fqdn, api_key_id, api_key, table)

