# Version 5.1.1

from flask import Flask, render_template, request
import logicmonitor_sdk
from logicmonitor_sdk.rest import ApiException
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO)

# === LogicMonitor API Configuration ===
lmconfig = logicmonitor_sdk.Configuration()
lmconfig.company = 'align'
lmconfig.access_id = '3sG44q9cJk7VD674EydM'
lmconfig.access_key = '(=(+rHtgLSmqDCrq7r3Pev6T(=Q9_qDVyA8}_]p='

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

@app.route('/')
def form():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    data = request.form
    logging.info(f"Received form data: {data}")  # <-- Debug input

    client_name = data['client_name']
    company_name = data['company_name']
    company_id = data['company_id']
    root_folder_id = 2

    new_client_folder_id = create_folder(api_instance, root_folder_id, client_name)
    logging.info(f"New client folder ID: {new_client_folder_id}")
    if not new_client_folder_id:
        return "Error creating client folder."

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

    adlumin_props = [
        {"name": "Adlumin.api.key", "value": data["adlumin_api_key"]},
        {"name": "adlumin.azure.client.id", "value": data["adlumin_client_id"]},
        {"name": "adlumin.azure.client.key", "value": data["adlumin_client_key"]},
        {"name": "adlumin.azure.tenant.id", "value": data["adlumin_tenant_id"]},
        {"name": "Adlumin.Tenant.id", "value": data["adlumin_tenant_id_2"]}
    ]
    logging.info(f"Adlumin properties: {adlumin_props}")

    adlumin_name = f"Adlumin Cloud - {client_name}"
    adlumin_device_id = add_lm_device(
        api_instance,
        new_client_folder_id,
        adlumin_name,
        data["adlumin_hostname"],
        int(data["adlumin_collector_id"]),
        adlumin_props
    )
    logging.info(f"Adlumin device ID returned: {adlumin_device_id}")

    return f"Client '{client_name}' created successfully in LogicMonitor."


if __name__ == '__main__':
    app.run(debug=True)
