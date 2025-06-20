# Version 6.1.2

from flask import Flask, render_template, request
import logicmonitor_sdk
from logicmonitor_sdk.rest import ApiException
import logging
import json
import re
from datetime import datetime, timedelta, timezone


import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# app version

APP_VERSION = "v6.1.2"

# Configure logging
logging.basicConfig(level=logging.INFO)

# function to get LM auth from keyvault
def get_lm_credentials_from_keyvault():
    with open('config.json') as f:
        config = json.load(f)

    vault_name = config["AzureKeyVault"]
    kv_url = f"https://{vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=kv_url, credential=credential)

    access_id_secret = config["LogicMonitor"]["access_id-secret"]
    access_key_secret = config["LogicMonitor"]["access_key-secret"]

    access_id = client.get_secret(access_id_secret).value
    access_key = client.get_secret(access_key_secret).value
    company = config["LogicMonitor"]["company"]

    return company, access_id, access_key


# === LogicMonitor API Configuration ===
company, access_id, access_key = get_lm_credentials_from_keyvault()

lmconfig = logicmonitor_sdk.Configuration()
lmconfig.company = company
lmconfig.access_id = access_id
lmconfig.access_key = access_key

# Initialize API Client
api_instance = logicmonitor_sdk.LMApi(logicmonitor_sdk.ApiClient(lmconfig))

app = Flask(__name__)

group_settings = [
    ("_Collectors", lambda path: f"join(system.staticgroups,\",\") =~ \"{path}/\" && isCollectorDevice()", False),
    ("_Domain Controllers", lambda path: f"system.displayname =~ \"DC-\" && displayname !~ \"networkinterface\" && displayname !~ \"iDRAC\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Firewalls", lambda path: f"system.displayname =~ \"-fw\" && join(system.staticgroups,\",\") =~ \"{path}/\"", True),
    ("_Routers", lambda path: f"system.displayname =~ \"^rt\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Switches", lambda path: f"(system.displayname =~ \"^sw\" || system.displayname =~ \"-asw\" || system.displayname =~ \"-sw\") && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Wireless", lambda path: f"system.displayname =~ \"^*-wap\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Disabled", lambda path: f"(system.displayname =~ \"-test`$\" || system.azure.resourcegroupname =~ \"-test\" || system.azure.status =~ \"deallocated\" || system.azure.resourcegroupname =~ \"-desktops\") && join(system.staticgroups,\",\") =~ \"{path}/\"", False)
]

#################### FUNCTIONS ####################

def validateIP(req: func.HttpRequest, config):
    logging.info("In validateIP")
    if req.headers.get('X-Forwarded-For') is None:
        ip = req.headers.get('X-Real-IP', req.remote_addr)
    else:
        ip = req.headers['X-Forwarded-For'].split(',')[0]
    if ip:
        ip = ip.split(':')[0]
        if ip == '127.0.0.1':
            logging.info("Localhost access allowed")
            return True
        allowed = config['IPsAllowed']
        if allowed and ip in allowed:
            logging.info(f"Allowed {ip}")
            return True
    logging.info(f"Not Allowed: {ip}")
    return False
 

def add_sdt_to_device_group(api_instance, group_id, duration_days):
    if duration_days <= 0:
        logging.info("No SDT added: user input was 0 days.")
        return

    now = datetime.now(timezone.utc)
    start = int((now + timedelta(minutes=1)).timestamp() * 1000)  # Ensure it's in the future
    end = int((now + timedelta(days=duration_days)).timestamp() * 1000)

    sdt_payload = logicmonitor_sdk.models.ResourceGroupSDT(
        type="ResourceGroupSDT",
        device_group_id=group_id,
        start_date_time=start,
        end_date_time=end,
        timezone="America/New_York",
        comment="Initial setup SDT",
        is_effective=True
    )

    try:
        response = api_instance.add_sdt(sdt_payload)
        logging.info(f"SDT added successfully to group ID {group_id}.")
    except ApiException as e:
        logging.error(f"Failed to add SDT to group {group_id}: {e}")



def fetch_collectors():
    try:
        response = api_instance.get_collector_list(size=1000)
        collectors = response.items

        # Filter active collectors and sort by ID
        sorted_collectors = sorted(
            [(c.id, f"{c.description or c.hostname} (ID: {c.id})") for c in collectors if c.status == 1],
            key=lambda x: x[1].lower()  # sort by name (case-insensitive)
        )

        return sorted_collectors
    except ApiException as e:
        logging.error(f"Failed to fetch collectors: {e}")
        return []


 
def create_folder(api_instance, parent_folder_id, folder_name):
    try:
        folder = logicmonitor_sdk.DeviceGroup(name=folder_name, parent_id=parent_folder_id)
        response = api_instance.add_device_group(folder)
        logging.info(f"Folder '{folder_name}' created. ID: {response.id}")
        return response.id
    except ApiException as e:
        logging.error(f"Failed to create folder '{folder_name}': {e}")
        return None

def add_client_folder_properties(api_instance, folder_id, company_name, company_id):
    try:
        properties = [
            {"name": "company.name", "value": company_name},
            {"name": "connectwisev2.companyid", "value": company_id}
        ]
        for prop in properties:
            prop_obj = logicmonitor_sdk.models.EntityProperty(name=prop["name"], value=prop["value"])
            api_instance.add_device_group_property(folder_id, prop_obj)
        logging.info(f"Properties added to folder ID {folder_id}")
    except ApiException as e:
        logging.error(f"Failed to add properties to folder ID {folder_id}: {e}")

def create_main_folder_structure(api_instance, client_folder_id):
    try:
        main_folder_id = create_folder(api_instance, client_folder_id, "Main")
        if not main_folder_id:
            return
        for subfolder in ["Network", "Power", "Services"]:
            create_folder(api_instance, main_folder_id, subfolder)
    except ApiException as e:
        logging.error(f"Failed to create 'Main' structure: {e}")

def create_device_groups(api_instance, parent_device_group_id):
    try:
        parent_group = api_instance.get_device_group_by_id(parent_device_group_id)
        path = parent_group.full_path
        for name, query_func, enable_netflow in group_settings:
            query = query_func(path)
            create_dynamic_group(api_instance, parent_device_group_id, name, query, enable_netflow)
    except ApiException as e:
        logging.error(f"Failed to create dynamic groups: {e}")

def create_dynamic_group(api_instance, parent_id, name, query, enable_netflow=False):
    try:
        existing_groups = api_instance.get_device_group_by_id(parent_id).sub_groups
        if any(group.name == name for group in existing_groups):
            return
        new_group = logicmonitor_sdk.DeviceGroup(
            name=name,
            parent_id=parent_id,
            applies_to=query,
            enable_netflow=enable_netflow
        )
        api_instance.add_device_group(new_group)
    except ApiException as e:
        logging.error(f"Failed to create dynamic group '{name}': {e}")

# general function to add a device to a logic monitor client (could be defender, adlumin, etc...)
def add_lm_device(api_instance, parent_folder_id, device_name, hostname, collector_id, properties):
    try:
        if collector_id <= 0:
            logging.error("Invalid collector ID")
            return
        device_payload = {
            "hostGroupIds": str(parent_folder_id),
            "name": hostname,
            "displayName": device_name,
            "preferredCollectorId": collector_id,
            "customProperties": properties
        }
        response = api_instance.add_device(device_payload)
        logging.info(f"Device '{device_name}' added successfully.")
        return response.id
    except ApiException as e:
        logging.error(f"Failed to add device '{device_name}': {e}")
        return None

def generate_adlumin_hostname(company_name):
    # remove non-alphanumeric characters
    cleaned = re.sub(r'[^a-zA-Z0-9]', '', company_name)
    return cleaned.lower() + ".portal.adlumin.com"

@app.route('/')
def form():

    with open('config.json') as f:
        config = json.load(f)

    if not validateIP(req, config):
        logging.info("IP validation failed in /")
        return func.HttpResponse("Forbidden", status_code=403)
    
    collector_options = fetch_collectors()
    return render_template('index.html', collectors=collector_options, version=APP_VERSION)

@app.route('/submit', methods=['POST'])
def submit():

    with open('config.json') as f:
        config = json.load(f)

    if not validateIP(req, config):
        logging.info("IP validation failed in /submit")
        return func.HttpResponse("Forbidden", status_code=403)

    data = request.form
    logging.info(f"Received form data: {data}")  # <-- Debug input

    required_fields = [
        "client_name", "company_name", "company_id",
        "defender_hostname", "defender_collector_id",
        "azure_client_id", "azure_client_key", "azure_mcas_pass", "azure_mcas_url", "azure_tenant_id",
        "adlumin_client_id", "adlumin_client_key", "adlumin_tenant_id", "adlumin_tenant_id_2"
    ]

    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return f"Error: Missing required fields: {', '.join(missing_fields)}", 400


    client_name = data['client_name']
    company_name = data['company_name']
    company_id = data['company_id']
    root_folder_id = 2

    new_client_folder_id = create_folder(api_instance, root_folder_id, client_name)
    logging.info(f"New client folder ID: {new_client_folder_id}")

    if not new_client_folder_id:
        return "Error creating client folder."
        logging.info()

    add_client_folder_properties(api_instance, new_client_folder_id, company_name, company_id)
    logging.info("Client folder properties added.")

    create_main_folder_structure(api_instance, new_client_folder_id)
    create_device_groups(api_instance, new_client_folder_id)

    defender_props = [
        {"name": "azure.client.id", "value": data["azure_client_id"]},
        {"name": "azure.client.key", "value": data["azure_client_key"]},
        {"name": "azure.client.mcas.pass", "value": data["azure_mcas_pass"]},
        {"name": "azure.client.mcas.url", "value": data["azure_mcas_url"]},
        {"name": "azure.tenant.id", "value": data["azure_tenant_id"]}
    ]
    logging.info(f"Defender properties: {defender_props}")

    defender_name = f"Microsoft Defender - {client_name}"
    defender_device_id = add_lm_device(
        api_instance,
        new_client_folder_id,
        defender_name,
        data["defender_hostname"],
        int(data["defender_collector_id"]),
        defender_props
    )
    logging.info(f"Defender device ID returned: {defender_device_id}")

    adlumin_props = []

    # Conditionally add optional field
    adlumin_api_key = data.get("adlumin_api_key", "").strip()
    if adlumin_api_key:
        adlumin_props.append({"name": "Adlumin.api.key", "value": adlumin_api_key})

    # Add mandatory fields
    adlumin_props.extend([
        {"name": "adlumin.azure.client.id", "value": data["adlumin_client_id"]},
        {"name": "adlumin.azure.client.key", "value": data["adlumin_client_key"]},
        {"name": "adlumin.azure.tenant.id", "value": data["adlumin_tenant_id"]},
        {"name": "Adlumin.Tenant.id", "value": data["adlumin_tenant_id_2"]}
    ])

    logging.info(f"Adlumin properties: {adlumin_props}")

    adlumin_name = f"Adlumin Cloud - {client_name}"
    adlumin_device_id = add_lm_device(
        api_instance,
        new_client_folder_id,
        adlumin_name,
        generate_adlumin_hostname(client_name),
        int(data["adlumin_collector_id"]),
        adlumin_props
    )
    logging.info(f"Adlumin device ID returned: {adlumin_device_id}")

    sdt_duration = int(data.get("sdt_duration", 0))
    if sdt_duration > 0:
        add_sdt_to_device_group(api_instance, new_client_folder_id, sdt_duration)

    return f"Client '{client_name}' created successfully in LogicMonitor."

 
if __name__ == '__main__':
    app.run(debug=True)


# create checkbox for adlumin and defender