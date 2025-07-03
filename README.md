# VMware VM Information Exporter

This script connects to a VMware vCenter server and exports comprehensive information about your VMware environment to an Excel file with multiple sheets.

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

### Command Line Arguments

Run the script with the following command:

```bash
python get_vm_info.py <vcenter_host> <username> <password> [output_dir]
```

Example:
```bash
python get_vm_info.py vcenter.example.com administrator password123 custom_output
```

### Configuration File

Alternatively, you can create a `.rv3.conf` file in the same directory with your credentials:

```ini
[vcenter]
host = your_vcenter_host
username = your_username
password = your_password
```

Then run the script without arguments:
```bash
python get_vm_info.py
```

## Output

The script creates an Excel file named `vmware_info_YYYYMMDD_HHMMSS.xlsx` in the specified output directory (defaults to 'output' if not specified). The file contains the following sheets:

1. VM Information - Basic VM details
2. CPU Information - CPU configuration
3. Memory Information - Memory configuration
4. Disk Information - Virtual disk details
5. Partition Information - Guest OS disk partitions
6. Network Information - Network adapter details
7. Floppy Drive Information - Floppy drive configuration
8. CD/DVD Drive Information - CD/DVD drive configuration
9. Snapshot Information - VM snapshot details
10. VMware Tools Information - VMware Tools status
11. Host Information - ESXi host details
12. Cluster Information - Cluster configuration
13. Datastore Information - Storage details
14. vSwitch Information - Virtual switch configuration
15. Portgroup Information - Port group settings
16. Host Network Interface Information - Host network adapters
17. Host Bus Adapter Information - Storage adapters
18. License Information - License details
19. Service Information - Host services
20. Health Information - System health status
21. Resource Pool Information - Resource pool configuration

## Output Directory

- If no output directory is specified, files will be saved in the 'output' directory
- The output directory will be created automatically if it doesn't exist
- Each run creates a new file with a timestamp to prevent overwriting
- Example output path: `output/vmware_info_20240321_123456.xlsx`

## Security Note

This script disables SSL certificate verification for simplicity. In a production environment, you should properly configure SSL certificates for secure communication with vCenter. 


This project is licensed under the Apache License 2.0 by Technology Pathfinders Consulting, LLC.