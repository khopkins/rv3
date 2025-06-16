# VMware VM Information Exporter

This script connects to a VMware vCenter server and exports information about all VMs to a CSV file.

## Prerequisites

- Python 3.6 or higher
- Access to a VMware vCenter server
- Valid credentials for the vCenter server

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the script with the following command:

```bash
python get_vm_info.py <vcenter_host> <username> <password>
```

Example:
```bash
python get_vm_info.py vcenter.example.com administrator password123
```

The script will create a CSV file named `vm_info_YYYYMMDD_HHMMSS.csv` in the current directory containing the following information for each VM:

- Name
- Power State
- CPU Count
- Memory (MB)
- Guest OS
- IP Address
- Host
- Datastore
- Folder
- UUID

## Security Note

This script disables SSL certificate verification for simplicity. In a production environment, you should properly configure SSL certificates for secure communication with vCenter. 