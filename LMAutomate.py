# Version 3.1.1

import logicmonitor_sdk
from logicmonitor_sdk.rest import ApiException
import logging
import json

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# === LogicMonitor API Configuration ===
lmconfig = logicmonitor_sdk.Configuration()
lmconfig.company = 'align'  # Replace with your LogicMonitor company name
lmconfig.access_id = '3sG44q9cJk7VD674EydM'  # Replace with your LogicMonitor API Access ID
lmconfig.access_key = '(=(+rHtgLSmqDCrq7r3Pev6T(=Q9_qDVyA8}_]p='  # Replace with your LogicMonitor API Access Key

# Initialize API Client
api_instance = logicmonitor_sdk.LMApi(logicmonitor_sdk.ApiClient(lmconfig))

# === Dynamic Group Settings ===
group_settings = [
    ("_Collectors", lambda path: f"join(system.staticgroups,\",\") =~ \"{path}/\" && isCollectorDevice()", False),
    ("_Domain Controllers", lambda path: f"system.displayname =~ \"DC-\" && displayname !~ \"networkinterface\" && displayname !~ \"iDRAC\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Firewalls", lambda path: f"system.displayname =~ \"-fw\" && join(system.staticgroups,\",\") =~ \"{path}/\"", True),
    ("_Routers", lambda path: f"system.displayname =~ \"^rt\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Switches", lambda path: f"(system.displayname =~ \"^sw\" || system.displayname =~ \"-asw\" || system.displayname =~ \"-sw\") && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Wireless", lambda path: f"system.displayname =~ \"^*-wap\" && join(system.staticgroups,\",\") =~ \"{path}/\"", False),
    ("_Disabled", lambda path: f"(system.displayname =~ \"-test`$\" || system.azure.resourcegroupname =~ \"-test\" || system.azure.status =~ \"deallocated\" || system.azure.resourcegroupname =~ \"-desktops\") && join(system.staticgroups,\",\") =~ \"{path}/\"", False)
]

# === Function to Create a Folder ===
def create_folder(api_instance, parent_folder_id, folder_name):
    """
    Creates a folder (device group) in LogicMonitor under the given parent folder ID.
    Returns the ID of the created folder, or None if creation fails.
    """
    try:
        folder = logicmonitor_sdk.DeviceGroup(name=folder_name, parent_id=parent_folder_id)
        response = api_instance.add_device_group(folder)
        logging.info(f"Folder '{folder_name}' created. ID: {response.id}")
        return response.id
    except ApiException as e:
        logging.error(f"Failed to create folder '{folder_name}': {e}")
        return None

# === Function to Add Client Folder Properties ===
def add_client_folder_properties(api_instance, folder_id):
    """
    Prompts the user for client-specific properties and adds them to the client folder.
    Ensures 'company.name' and 'connectwisev2.companyid' are set.
    """
    try:
        company_name = input("Enter the Company Name for this client: ").strip()
        company_id = input("Enter the ConnectWise Company ID: ").strip()

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

# === Function to Create "Main" Folder and Subfolders ===
def create_main_folder_structure(api_instance, client_folder_id):
    """
    Creates a 'Main' folder inside the client folder.
    Inside 'Main', creates 'Network', 'Power', and 'Services' subfolders.
    """
    try:
        # Create the 'Main' folder inside the client folder
        main_folder_id = create_folder(api_instance, client_folder_id, "Main")
        if not main_folder_id:
            logging.error("Failed to create 'Main' folder. Skipping subfolder creation.")
            return
        
        # Create subfolders inside 'Main'
        subfolders = ["Network", "Power", "Services"]
        for subfolder in subfolders:
            create_folder(api_instance, main_folder_id, subfolder)

    except ApiException as e:
        logging.error(f"Failed to create 'Main' folder structure: {e}")

# === Function to Create Dynamic Groups ===
def create_device_groups(api_instance, parent_device_group_id):
    """
    Creates predefined dynamic groups as subgroups under the specified parent folder.
    Uses predefined AppliesTo queries to filter devices.
    """
    try:
        # Get the full path of the parent device group
        parent_group = api_instance.get_device_group_by_id(parent_device_group_id)
        path = parent_group.full_path

        for name, query_func, enable_netflow in group_settings:
            query = query_func(path)
            create_dynamic_group(api_instance, parent_device_group_id, name, query, enable_netflow)

    except ApiException as e:
        logging.error(f"Failed to create dynamic groups: {e}")

# === Function to Create a Dynamic Group (with AppliesTo Query) ===
def create_dynamic_group(api_instance, parent_id, name, query, enable_netflow=False):
    """
    Creates a dynamic group with an AppliesTo query in LogicMonitor.
    Ensures the group does not already exist before attempting to create it.
    """
    try:
        # Check if the group already exists
        existing_groups = api_instance.get_device_group_by_id(parent_id).sub_groups
        if any(group.name == name for group in existing_groups):
            logging.info(f"Dynamic group '{name}' already exists under parent ID {parent_id}.")
            return

        # Create the group
        new_group = logicmonitor_sdk.DeviceGroup(
            name=name,
            parent_id=parent_id,
            applies_to=query,
            enable_netflow=enable_netflow
        )
        response = api_instance.add_device_group(new_group)
        logging.info(f"Dynamic group '{name}' created under parent ID {parent_id}. ID: {response.id}")

    except ApiException as e:
        logging.error(f"Failed to create dynamic group '{name}': {e}")

# === Function to Add Microsoft Defender Device ===
def add_defender(api_instance, parent_folder_id, device_name, hostname, collector_id):
    """
    Adds Microsoft Defender under the specified client folder.
    Uses `preferredCollectorGroupId` instead of `system.collectorid` for assigning the Collector.
    """
    try:
        if collector_id <= 0:
            logging.error("Invalid Collector ID. Please use a valid Collector ID from LogicMonitor.")
            return None

        # Create the device payload with the correct Collector assignment
        device_payload = {
            "hostGroupIds": str(parent_folder_id),  # Assign device to the correct client folder
            "name": hostname,
            "displayName": device_name,
            "preferredCollectorId": collector_id # Correct way to assign collector
            
            
        }

        logging.info(f"Adding device with parameters: {json.dumps(device_payload, indent=2)}")
        response = api_instance.add_device(device_payload)
        logging.info(f"Microsoft Defender added successfully. Device ID: {response.id}")
        return response.id

    except ApiException as e:
        logging.error(f"Failed to add Microsoft Defender: {e}")
        return None


# === Main Function ===
def main():
    """
    Main execution function. Handles user input, folder creation, 
    client properties, dynamic groups, and the "Main" folder structure.
    """
    # Get client details from the user
    client_name = input("Enter the Client Name: ").strip()

    # Root folder ID under which all clients' folders are created
    root_folder_id = 2  # Client folder ID

    # Step 1: Create the client folder
    new_client_folder_id = create_folder(api_instance, root_folder_id, client_name)
    if not new_client_folder_id:
        logging.error("Failed to create client folder. Exiting.")
        return

    # Step 2: Prompt user for client folder properties and add them
    add_client_folder_properties(api_instance, new_client_folder_id)

    # Step 3: Create "Main" folder and its subfolders inside the client folder
    create_main_folder_structure(api_instance, new_client_folder_id)

    # Step 4: Create dynamic groups as subfolders
    create_device_groups(api_instance, new_client_folder_id)

    # Step 5: Add Microsoft Defender as a device
    device_name = f"Microsoft Defender - {client_name}"
    hostname = "www.example.com"

    # Get user input for Collector ID
    collector_id = input("Enter the Collector ID for Microsoft Defender: ").strip()
    if not collector_id.isdigit():
        logging.error("Error: Collector ID must be a number.")
        return
    collector_id = int(collector_id)

    # Add Microsoft Defender device to the newly created client folder
    add_defender(api_instance, new_client_folder_id, device_name, hostname, collector_id)


# === Entry Point ===
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
