import csv
import pandas as pd
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google.cloud import storage
from google.cloud import secretmanager_v1 as secretmanager
import os
import tempfile
import configparser

import json
import requests
import googleapiclient
from datetime import datetime

# Set the credentials globally so that it can be used across functions
credentials = None

# Set the service globally so that it can be used across functions
service = None

user_service = None
def create_credentials(service_account_key_path):
    global credentials
    credentials = service_account.Credentials.from_service_account_file(
        service_account_key_path,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    return credentials

def create_service():
    global service
    if credentials is None:
        raise ValueError("Credentials not initialized. Call create_credentials first.")
    service = build("iam", "v1", credentials=credentials)
    return service


def create_user_service():
    global user_service 
    if credentials is None:
        raise ValueError("Credentials not initialized. Call create_credentials first.")
    user_service = build('cloudresourcemanager', 'v1', credentials=credentials)
    return user_service
        

def get_key_usage(service_account_email: str, key_data: dict) -> dict:
    """Get key usage information."""
    try:
        key_id = key_data.get("name", "").split("/")[-1]
        url = f"https://cloudkms.googleapis.com/v1/projects/-/locations/global/keyRings/_/cryptoKeys/_/cryptoKeyVersions/{key_id}"
        
        response = requests.get(url, headers={'Authorization': f'Bearer {credentials.token}'})
        response_data = response.json()
        # print(response_data)

        return {
            "last_used_time": response_data.get("lastUsedTime", "N/A"),
            "usage": response_data.get("algorithm", "N/A"),

        }

    except Exception as e:
        print(f"Error fetching key usage for service account {service_account_email}, key {key_id}: {e}")
        return {"last_used_time": "N/A", "usage": "N/A"}
    

def list_iam_policies_for_all_service_accounts(project_id: str) -> list:
    try:
        policies_data = []
        # Create the service
        create_service()

        # List all service accounts in the project
        service_accounts = (
            service.projects()
            .serviceAccounts()
            .list(name=f"projects/{project_id}")
            .execute()
        )

        for account in service_accounts.get("accounts", []):
            service_account_email = account["email"]
            # Get IAM policies for the service account
            policies = get_iam_policies(service_account_email)

            policies_data.append(
                {
                    "service_account_email": service_account_email,
                    "iam_policies": policies,
                }
            )

        return policies_data

    except googleapiclient.errors.HttpError as e:
        print(f"Error listing service accounts: {e}")
        return []

def get_iam_policies(service_account_email: str) -> dict:
    try:
        # Create the service
        create_service()

        # Get IAM policies for the service account
        policies = service.projects().serviceAccounts().getIamPolicy(
            resource=f"projects/-/serviceAccounts/{service_account_email}"
        ).execute()

        return policies

    except googleapiclient.errors.HttpError as e:
        print(f"Error getting IAM policies for service account {service_account_email}: {e}")
        return {}




def list_keys_for_all_service_accounts(project_id: str) -> list:
    try:
        keys_data = []
        # Create the service
        create_service()

        # List all service accounts in the project
        service_accounts = (
            service.projects()
            .serviceAccounts()
            .list(name=f"projects/{project_id}")
            .execute()
        )

        for account in service_accounts.get("accounts", []):
            service_account_email = account["email"]
            # List all keys for the service account
            keys_response = service.projects().serviceAccounts().keys().list(
                name=f"projects/{project_id}/serviceAccounts/{service_account_email}"
            ).execute()
         
            for key in keys_response.get("keys", []):
                key_info = {
                    "service_account_email": service_account_email,
                    "key_id": key.get("name", "").split("/")[-1],
                    "created": key.get("validAfterTime", "N/A"),
                    "expires": key.get("validBeforeTime", "N/A"),
                    "state": key.get("keyState", "N/A"),
                    "last_used_time": key.get("validAfterTime", "N/A"),
                    "keyAlgorithm": key.get("keyAlgorithm", "N/A"),
                    "keyOrigin":key.get("keyOrigin","N/A"),
                    "keyType":key.get("keyType","N/A")
                }
                key_info.update(get_key_usage(service_account_email, key))
                keys_data.append(key_info)

        return keys_data

    except googleapiclient.errors.HttpError as e:
        print(f"Error listing service accounts: {e}")
        return []


def export_iam_policies_to_excel(project_id, service_account_key_path):
    create_user_service()

    policy_request = user_service.projects().getIamPolicy(resource=project_id, body={})
    policy_response = policy_request.execute()
    iam_policies = policy_response.get('bindings', [])

    data = {'Role': [], 'ServiceAccounts': [], 'Users': []}

    for policy in iam_policies:
        service_accounts = []
        users = []

        for member in policy['members']:
            if member.startswith('serviceAccount:'):
                service_accounts.append(member[len('serviceAccount:'):])
            elif member.startswith('user:'):
                users.append(member[len('user:'):])

        data['Role'].append(policy['role'])
        data['ServiceAccounts'].append(', '.join(service_accounts))
        data['Users'].append(', '.join(users))

    df = pd.DataFrame(data)
    return df

def upload_to_gcp_temp_bucket(temp_file_path, bucket_name, blob_name):
    """Uploads a file to the Google Cloud Storage bucket."""
    try:
        client = storage.Client()
        bucket = client.get_bucket(bucket_name)
        blob = bucket.blob(blob_name)

        blob.upload_from_filename(temp_file_path)

        print(f"File {temp_file_path} uploaded to {bucket_name}/{blob_name}.")
    except Exception as e:
        print(f"Error uploading file to Google Cloud Storage: {e}")



def service_request(credentials):
    return credentials.authorized_session()


def trigger():
    config = configparser.ConfigParser()
    config.read('config.ini')  # Provide the path to your INI file

    # Get the configuration values from the INI file
    google_cloud_config = config['GoogleCloud']

    # Replace with your own values from the INI file
    project_id = google_cloud_config.get('PROJECT_ID')
    secret_name = google_cloud_config.get('SECRET_NAME')
    # service_account_email = google_cloud_config.get('service_account_email')
    location =  google_cloud_config.get('location')  
    function_name =  google_cloud_config.get('functionname')

    # Create a Secret Manager client
    client = secretmanager.SecretManagerServiceClient()

    # Access the latest version of the secret
    secret_version = client.access_secret_version(name=f"projects/{project_id}/secrets/{secret_name}/versions/latest")

    # Get the JSON data from the secret
    json_data1 = secret_version.payload.data.decode("UTF-8")
    # json_data = json.loads(json_data1)
    # Clean the data by removing newlines and spaces
    j =  json_data1.replace("\n","").split(",")
    # Print the JSON data
    data_str = "{\n" + ",\n".join(j) + "\n}"

    # Parse the string as JSON
    parsed_data = json.loads(data_str)

    # Print the JSON object
    j = json.dumps(parsed_data, indent=2)
    # print(j)
    # pip install google-cloud-documentai
    url = f"https://{location}-{project_id}.cloudfunctions.net/{function_name}"
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = j
    json_credentials = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    data_dict = json.loads(j)
    # print(data_dict)
    # Create a credentials object from the JSON string
    credentials = service_account.Credentials.from_service_account_info(
        data_dict, scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )

    # Build the authenticated service
    service = build("cloudfunctions", "v1", credentials=credentials)
    # print(data_dict)
    # Make a request to the function (you can pass request data if needed)
    # response = service.projects().locations().functions().call(
    #     name = f"projects/{project_id}/locations/us-central1/functions/gcp-iam-fun",
    #     body={"data":j}

    # ).execute()
    return j






def main_call_fun(request,context):

    try:
        # request_json = request.get_json(silent=True)
        data_dict = json.loads(trigger())
        request_json = data_dict
        
 
        # Load configuration from the INI file
        config = configparser.ConfigParser()
        config.read('config.ini')

        # Extract configuration values
        project_id = config.get('GoogleCloud', 'project_id')
        # secret_name = config.get('GoogleCloud', 'secret_name')
        bucket_name = config.get('GoogleCloud', 'bucket_name')
        blob_name = datetime.now().strftime("_%Y%m%d_%H%M%S") + "-" + config.get('GoogleCloud', 'blob_name')
        service_account_key_file = config.get('GoogleCloud', 'service_account_key_file')
        print(bucket_name)
        print(service_account_key_file)
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        print(request_json.get("type", "N/A"))      
        # Full path to the temporary XLSX file
        temp_xlsx_file = os.path.join(temp_dir, blob_name)
        secret_json = {
                        "type": request_json.get("type", "N/A"),
                        "project_id": request_json.get("project_id", "N/A"),
                        "private_key_id": request_json.get("private_key_id", "N/A"),
                        "private_key": request_json.get("private_key", "N/A")  ,
                        "client_email": request_json.get("client_email", "N/A"),
                        "client_id": request_json.get("client_id", "N/A"),
                        "auth_uri": request_json.get("auth_uri", "N/A"),
                        "token_uri": request_json.get("token_uri", "N/A"),
                        "auth_provider_x509_cert_url": request_json.get("auth_provider_x509_cert_url", "N/A"),
                        "client_x509_cert_url": request_json.get("client_x509_cert_url", "N/A"),
                        "universe_domain": request_json.get("universe_domain", "N/A")
                        }
        # print(secret_json)
        # Check if any key has the value "N/A"
        if any(value == "N/A" for value in secret_json.values()):
            raise ValueError("Error: One or more keys have the value 'N/A'")
        local_file_path =  os.path.join(temp_dir, service_account_key_file)
        print(local_file_path)
            # Write the secret to a local file
        with open(local_file_path, 'w') as f:
            json.dump(secret_json, f)
        print(local_file_path)
        SERVICE_ACCOUNT_KEY_PATH = local_file_path
        create_credentials(SERVICE_ACCOUNT_KEY_PATH)
        # List keys for all service accounts and IAM policies for all service accounts
        keys_data = list_keys_for_all_service_accounts(project_id)
        iam_policies_data = list_iam_policies_for_all_service_accounts(project_id)
        user_data = export_iam_policies_to_excel(project_id, SERVICE_ACCOUNT_KEY_PATH)
        print(user_data)
        # Convert the data to pandas DataFrames
        keys_df = pd.DataFrame(keys_data)
        iam_policies_df = pd.DataFrame(iam_policies_data)

        # Save DataFrames to an Excel file with different sheets in the temporary directory
        with pd.ExcelWriter(temp_xlsx_file, engine='xlsxwriter') as writer:
            keys_df.to_excel(writer, sheet_name='ServiceAccountKeys', index=False)
            iam_policies_df.to_excel(writer, sheet_name='IAMPolicies', index=False)
            user_data.to_excel(writer, sheet_name='userinfo', index=False)

        bucket_name = bucket_name
        file_path = temp_xlsx_file  # Replace with the path to the file you want to upload
        client = storage.Client.from_service_account_info(secret_json)

        # client = storage.Client()
        bucket = client.get_bucket(bucket_name)
        blob = bucket.blob(blob_name)

        blob.upload_from_filename(file_path)

        print(f"File {file_path} uploaded to {bucket_name}/{blob_name}.")
        return f"File {temp_xlsx_file} uploaded to {bucket_name}/{blob_name}."
    except Exception as e:
        return f"Error: {str(e)}"



# main_call_fun("request")
