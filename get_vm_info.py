#!/usr/bin/env python3

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl
import pandas as pd
from datetime import datetime
import sys
import os
import configparser

def read_config():
    """
    Read vCenter credentials from .rv3.conf file
    Returns tuple of (host, username, password) or None if config doesn't exist
    """
    config_file = '.rv3.conf'
    if not os.path.exists(config_file):
        return None
    
    config = configparser.ConfigParser()
    config.read(config_file)
    
    if 'vcenter' not in config:
        return None
    
    try:
        host = config['vcenter']['host']
        username = config['vcenter']['username']
        password = config['vcenter']['password']
        print(f"Using credentials from {config_file}")
        return host, username, password
    except KeyError:
        return None

def get_disk_info(vm):
    """Get disk information for a VM"""
    disk_info = []
    try:
        # Get all virtual disks
        for device in vm.config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualDisk):
                # Get storage info
                storage = vm.storage
                disk_size = device.capacityInKB * 1024  # Convert KB to bytes
                disk_size_gb = disk_size / (1024**3)    # Convert to GB
                
                # Get used space if available
                used_space = 'N/A'
                if hasattr(storage, 'perDatastoreUsage'):
                    for datastore_usage in storage.perDatastoreUsage:
                        if datastore_usage.datastore == device.backing.datastore:
                            used_space = datastore_usage.committed / (1024**3)  # Convert to GB
                            break
                
                disk_info.append({
                    'label': device.deviceInfo.label,
                    'size_gb': round(disk_size_gb, 2),
                    'used_gb': round(used_space, 2) if used_space != 'N/A' else 'N/A',
                    'datastore': device.backing.datastore.name if device.backing.datastore else 'N/A',
                    'disk_mode': device.backing.diskMode,
                    'thin_provisioned': device.backing.thinProvisioned if hasattr(device.backing, 'thinProvisioned') else 'N/A',
                    'controller': device.controllerKey,
                    'unit_number': device.unitNumber,
                    'sharing': device.sharing if hasattr(device, 'sharing') else 'N/A'
                })
    except Exception as e:
        print(f"Error getting disk info for {vm.name}: {str(e)}")
    
    return disk_info

def collect_properties(content, view_type, properties, container=None, verbose=False):
    """Helper function to collect properties from vCenter"""
    if container is None:
        container = content.rootFolder
    
    container_view = content.viewManager.CreateContainerView(
        container, [view_type], recursive=True
    )
    
    try:
        return content.propertyCollector.RetrieveContents(
            [obj_set for obj_set in content.propertyCollector.CreateFilter(
                container_view, properties, False
            ).spec]
        )
    finally:
        container_view.Destroy()

def get_datastore_info(content):
    """Get information about all datastores"""
    datastore_data = []
    
    try:
        # Get all datastores directly from the content
        container = content.rootFolder
        view_type = [vim.Datastore]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for datastore in container_view.view:
            try:
                print(f"Processing datastore: {datastore.name}")  # Debug print
                
                # Get capacity info
                capacity = datastore.summary.capacity
                free_space = datastore.summary.freeSpace
                used_space = capacity - free_space
                
                # Convert to GB
                capacity_gb = capacity / (1024**3)
                free_space_gb = free_space / (1024**3)
                used_space_gb = used_space / (1024**3)
                
                # Calculate usage percentage
                usage_percent = (used_space / capacity * 100) if capacity > 0 else 0
                
                # Get VM count
                vm_count = len(datastore.vm) if hasattr(datastore, 'vm') else 0
                
                # Get host count
                host_count = len(datastore.host) if hasattr(datastore, 'host') else 0
                
                datastore_info = {
                    'Name': datastore.name,
                    'Type': datastore.summary.type,
                    'Capacity (GB)': round(capacity_gb, 2),
                    'Free Space (GB)': round(free_space_gb, 2),
                    'Used Space (GB)': round(used_space_gb, 2),
                    'Usage %': round(usage_percent, 2),
                    'Status': datastore.summary.accessible,
                    'Multiple Host Access': datastore.summary.multipleHostAccess,
                    'URL': datastore.summary.url,
                    'VM Count': vm_count,
                    'Host Count': host_count,
                    'Maintenance Mode': datastore.summary.maintenanceMode if hasattr(datastore.summary, 'maintenanceMode') else 'N/A'
                }
                
                print(f"Datastore info collected: {datastore_info}")  # Debug print
                datastore_data.append(datastore_info)
                
            except Exception as e:
                print(f"Error getting datastore info for {datastore.name}: {str(e)}")
                datastore_data.append({
                    'Name': datastore.name,
                    'Type': 'N/A',
                    'Capacity (GB)': 'N/A',
                    'Free Space (GB)': 'N/A',
                    'Used Space (GB)': 'N/A',
                    'Usage %': 'N/A',
                    'Status': 'N/A',
                    'Multiple Host Access': 'N/A',
                    'URL': 'N/A',
                    'VM Count': 'N/A',
                    'Host Count': 'N/A',
                    'Maintenance Mode': 'N/A'
                })
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting datastore information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no datastores found
    if not datastore_data:
        print("No datastores found, creating empty DataFrame")  # Debug print
        datastore_columns = [
            'Name', 'Type', 'Capacity (GB)', 'Free Space (GB)', 'Used Space (GB)',
            'Usage %', 'Status', 'Multiple Host Access', 'URL', 'VM Count',
            'Host Count', 'Maintenance Mode'
        ]
        return pd.DataFrame(columns=datastore_columns)
    
    print(f"Total datastores found: {len(datastore_data)}")  # Debug print
    return pd.DataFrame(datastore_data)

def get_host_info(content):
    """Get information about all ESXi hosts"""
    host_data = []
    
    try:
        # Get all hosts directly from the content
        container = content.rootFolder
        view_type = [vim.HostSystem]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for host in container_view.view:
            try:
                print(f"Processing host: {host.name}")  # Debug print
                
                # Get CPU info
                cpu_info = host.hardware.cpuInfo
                cpu_cores = cpu_info.numCpuCores
                cpu_mhz = cpu_info.hz / 1000000  # Convert to MHz
                
                # Get memory info
                memory_size = host.hardware.memorySize / (1024**3)  # Convert to GB
                
                # Get network adapters
                network_adapters = []
                if hasattr(host.config, 'network'):
                    network_adapters = host.config.network.vnic
                
                # Get storage adapters
                storage_adapters = []
                if hasattr(host.config, 'storageDevice'):
                    storage_adapters = [adapter for adapter in host.config.storageDevice.hostBusAdapter 
                                     if isinstance(adapter, vim.host.BlockHba)]
                
                host_info = {
                    'Name': host.name,
                    'Status': host.runtime.connectionState,
                    'Power State': host.runtime.powerState,
                    'CPU Cores': cpu_cores,
                    'CPU Speed (MHz)': cpu_mhz,
                    'Memory (GB)': round(memory_size, 2),
                    'Version': host.config.product.version if hasattr(host.config, 'product') else 'N/A',
                    'Build': host.config.product.build if hasattr(host.config, 'product') else 'N/A',
                    'Vendor': host.hardware.systemInfo.vendor if hasattr(host.hardware, 'systemInfo') else 'N/A',
                    'Model': host.hardware.systemInfo.model if hasattr(host.hardware, 'systemInfo') else 'N/A',
                    'UUID': host.hardware.systemInfo.uuid if hasattr(host.hardware, 'systemInfo') else 'N/A',
                    'Boot Time': host.runtime.bootTime.replace(tzinfo=None) if host.runtime.bootTime else 'N/A',
                    'Maintenance Mode': host.runtime.inMaintenanceMode,
                    'Cluster': host.parent.name if isinstance(host.parent, vim.ClusterComputeResource) else 'N/A',
                    'Network Adapters': len(network_adapters),
                    'Storage Adapters': len(storage_adapters)
                }
                
                print(f"Host info collected: {host_info}")  # Debug print
                host_data.append(host_info)
                
            except Exception as e:
                print(f"Error getting host info for {host.name}: {str(e)}")
                host_data.append({
                    'Name': host.name,
                    'Status': 'Error',
                    'Power State': 'N/A',
                    'CPU Cores': 'N/A',
                    'CPU Speed (MHz)': 'N/A',
                    'Memory (GB)': 'N/A',
                    'Version': 'N/A',
                    'Build': 'N/A',
                    'Vendor': 'N/A',
                    'Model': 'N/A',
                    'UUID': 'N/A',
                    'Boot Time': 'N/A',
                    'Maintenance Mode': 'N/A',
                    'Cluster': 'N/A',
                    'Network Adapters': 'N/A',
                    'Storage Adapters': 'N/A'
                })
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting host information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no hosts found
    if not host_data:
        print("No hosts found, creating empty DataFrame")  # Debug print
        host_columns = [
            'Name', 'Status', 'Power State', 'CPU Cores', 'CPU Speed (MHz)',
            'Memory (GB)', 'Version', 'Build', 'Vendor', 'Model', 'UUID',
            'Boot Time', 'Maintenance Mode', 'Cluster', 'Network Adapters',
            'Storage Adapters'
        ]
        return pd.DataFrame(columns=host_columns)
    
    print(f"Total hosts found: {len(host_data)}")  # Debug print
    return pd.DataFrame(host_data)

def get_network_info(content):
    """Get information about all networks"""
    network_data = []
    
    try:
        # Get all networks directly from the content
        container = content.rootFolder
        view_type = [vim.Network]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for network in container_view.view:
            try:
                print(f"Processing network: {network.name}")  # Debug print
                
                # Get connected hosts and VMs
                connected_hosts = network.host if hasattr(network, 'host') else []
                connected_vms = network.vm if hasattr(network, 'vm') else []
                
                # Get network type
                network_type = type(network).__name__
                
                # Get additional info for distributed virtual portgroups
                dvswitch_name = 'N/A'
                vlan_id = 'N/A'
                num_ports = 'N/A'
                port_binding = 'N/A'
                
                if isinstance(network, vim.dvs.DistributedVirtualPortgroup):
                    if hasattr(network.config, 'distributedVirtualSwitch'):
                        dvswitch_name = network.config.distributedVirtualSwitch.name
                    if hasattr(network.config, 'defaultPortConfig') and hasattr(network.config.defaultPortConfig, 'vlan'):
                        vlan_id = network.config.defaultPortConfig.vlan.vlanId
                    if hasattr(network.config, 'numPorts'):
                        num_ports = network.config.numPorts
                    if hasattr(network.config, 'portBinding'):
                        port_binding = network.config.portBinding
                
                network_info = {
                    'Name': network.name,
                    'Type': network_type,
                    'Connected Hosts': len(connected_hosts),
                    'Connected VMs': len(connected_vms),
                    'Accessible': network.summary.accessible if hasattr(network, 'summary') else 'N/A',
                    'DVSwitch': dvswitch_name,
                    'VLAN ID': vlan_id,
                    'Num Ports': num_ports,
                    'Port Binding': port_binding
                }
                
                print(f"Network info collected: {network_info}")  # Debug print
                network_data.append(network_info)
                
            except Exception as e:
                print(f"Error getting network info for {network.name}: {str(e)}")
                network_data.append({
                    'Name': network.name,
                    'Type': 'N/A',
                    'Connected Hosts': 'N/A',
                    'Connected VMs': 'N/A',
                    'Accessible': 'N/A',
                    'DVSwitch': 'N/A',
                    'VLAN ID': 'N/A',
                    'Num Ports': 'N/A',
                    'Port Binding': 'N/A'
                })
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting network information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no networks found
    if not network_data:
        print("No networks found, creating empty DataFrame")  # Debug print
        network_columns = [
            'Name', 'Type', 'Connected Hosts', 'Connected VMs', 'Accessible',
            'DVSwitch', 'VLAN ID', 'Num Ports', 'Port Binding'
        ]
        return pd.DataFrame(columns=network_columns)
    
    print(f"Total networks found: {len(network_data)}")  # Debug print
    return pd.DataFrame(network_data)

def get_cluster_info(content):
    """Get information about all clusters"""
    cluster_data = []
    
    try:
        # Get all clusters directly from the content
        container = content.rootFolder
        view_type = [vim.ClusterComputeResource]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for cluster in container_view.view:
            try:
                print(f"Processing cluster: {cluster.name}")  # Debug print
                
                # Get total resources
                total_cpu = 0
                total_memory = 0
                total_vms = 0
                
                for host in cluster.host:
                    if hasattr(host, 'hardware'):
                        total_cpu += host.hardware.cpuInfo.numCpuCores
                        total_memory += host.hardware.memorySize
                    if hasattr(host, 'vm'):
                        total_vms += len(host.vm)
                
                # Convert memory to GB
                total_memory_gb = total_memory / (1024**3)
                
                # Get HA and DRS status
                ha_enabled = False
                drs_enabled = False
                
                if hasattr(cluster.configuration, 'dasConfig'):
                    ha_enabled = cluster.configuration.dasConfig.enabled
                if hasattr(cluster.configuration, 'drsConfig'):
                    drs_enabled = cluster.configuration.drsConfig.enabled
                
                cluster_info = {
                    'Name': cluster.name,
                    'Status': cluster.overallStatus if hasattr(cluster, 'overallStatus') else 'N/A',
                    'Total Hosts': len(cluster.host),
                    'Total VMs': total_vms,
                    'Total CPU Cores': total_cpu,
                    'Total Memory (GB)': round(total_memory_gb, 2),
                    'HA Enabled': ha_enabled,
                    'DRS Enabled': drs_enabled,
                    'Parent': cluster.parent.name if cluster.parent else 'N/A'
                }
                
                print(f"Cluster info collected: {cluster_info}")  # Debug print
                cluster_data.append(cluster_info)
                
            except Exception as e:
                print(f"Error getting cluster info for {cluster.name}: {str(e)}")
                cluster_data.append({
                    'Name': cluster.name,
                    'Status': 'Error',
                    'Total Hosts': 'N/A',
                    'Total VMs': 'N/A',
                    'Total CPU Cores': 'N/A',
                    'Total Memory (GB)': 'N/A',
                    'HA Enabled': 'N/A',
                    'DRS Enabled': 'N/A',
                    'Parent': 'N/A'
                })
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting cluster information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no clusters found
    if not cluster_data:
        print("No clusters found, creating empty DataFrame")  # Debug print
        cluster_columns = [
            'Name', 'Status', 'Total Hosts', 'Total VMs', 'Total CPU Cores',
            'Total Memory (GB)', 'HA Enabled', 'DRS Enabled', 'Parent'
        ]
        return pd.DataFrame(columns=cluster_columns)
    
    print(f"Total clusters found: {len(cluster_data)}")  # Debug print
    return pd.DataFrame(cluster_data)

def get_vswitch_info(content):
    """Get information about all vSwitches"""
    vswitch_data = []
    
    try:
        # Get all hosts
        container = content.rootFolder
        view_type = [vim.HostSystem]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for host in container_view.view:
            try:
                if hasattr(host.config, 'network'):
                    for vswitch in host.config.network.vswitch:
                        # Get port groups
                        port_groups = []
                        for pg in host.config.network.portgroup:
                            if pg.spec.vswitchName == vswitch.name:
                                port_groups.append(pg.spec.name)
                        
                        # Get physical NICs
                        pnics = []
                        for pnic in vswitch.pnic:
                            pnics.append(pnic.device)
                        
                        vswitch_info = {
                            'Host': host.name,
                            'Name': vswitch.name,
                            'Num Ports': vswitch.numPorts,
                            'Num Ports Available': vswitch.numPortsAvailable,
                            'MTU': vswitch.mtu,
                            'Port Groups': ', '.join(port_groups),
                            'Physical NICs': ', '.join(pnics),
                            'Allow Promiscuous': vswitch.spec.policy.security.allowPromiscuous if hasattr(vswitch.spec.policy, 'security') else 'N/A',
                            'Forged Transmits': vswitch.spec.policy.security.forgedTransmits if hasattr(vswitch.spec.policy, 'security') else 'N/A',
                            'MAC Changes': vswitch.spec.policy.security.macChanges if hasattr(vswitch.spec.policy, 'security') else 'N/A'
                        }
                        
                        vswitch_data.append(vswitch_info)
                
            except Exception as e:
                print(f"Error getting vSwitch info for host {host.name}: {str(e)}")
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting vSwitch information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no vSwitches found
    if not vswitch_data:
        vswitch_columns = [
            'Host', 'Name', 'Num Ports', 'Num Ports Available', 'MTU',
            'Port Groups', 'Physical NICs', 'Allow Promiscuous',
            'Forged Transmits', 'MAC Changes'
        ]
        return pd.DataFrame(columns=vswitch_columns)
    
    return pd.DataFrame(vswitch_data)

def get_vportgroup_info(content):
    """Get information about all portgroups"""
    portgroup_data = []
    
    try:
        # Get all hosts
        container = content.rootFolder
        view_type = [vim.HostSystem]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for host in container_view.view:
            try:
                if hasattr(host.config, 'network'):
                    for portgroup in host.config.network.portgroup:
                        # Get VLAN ID
                        vlan_id = 'N/A'
                        if hasattr(portgroup.spec, 'vlanId'):
                            vlan_id = portgroup.spec.vlanId
                        
                        # Get security policy
                        security_policy = {
                            'allow_promiscuous': 'N/A',
                            'forged_transmits': 'N/A',
                            'mac_changes': 'N/A'
                        }
                        
                        if hasattr(portgroup.spec, 'policy') and hasattr(portgroup.spec.policy, 'security'):
                            security = portgroup.spec.policy.security
                            security_policy = {
                                'allow_promiscuous': security.allowPromiscuous,
                                'forged_transmits': security.forgedTransmits,
                                'mac_changes': security.macChanges
                            }
                        
                        portgroup_info = {
                            'Host': host.name,
                            'Name': portgroup.spec.name,
                            'vSwitch': portgroup.spec.vswitchName,
                            'VLAN ID': vlan_id,
                            'Allow Promiscuous': security_policy['allow_promiscuous'],
                            'Forged Transmits': security_policy['forged_transmits'],
                            'MAC Changes': security_policy['mac_changes'],
                            'Active': portgroup.spec.vswitchName in [vs.name for vs in host.config.network.vswitch]
                        }
                        
                        portgroup_data.append(portgroup_info)
                
            except Exception as e:
                print(f"Error getting portgroup info for host {host.name}: {str(e)}")
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting portgroup information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no portgroups found
    if not portgroup_data:
        portgroup_columns = [
            'Host', 'Name', 'vSwitch', 'VLAN ID', 'Allow Promiscuous',
            'Forged Transmits', 'MAC Changes', 'Active'
        ]
        return pd.DataFrame(columns=portgroup_columns)
    
    return pd.DataFrame(portgroup_data)

def get_vnic_info(content):
    """Get information about all host network interfaces"""
    vnic_data = []
    
    try:
        # Get all hosts
        container = content.rootFolder
        view_type = [vim.HostSystem]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for host in container_view.view:
            try:
                if hasattr(host.config, 'network'):
                    for vnic in host.config.network.vnic:
                        # Get IP configuration
                        ip_config = vnic.spec.ip
                        ip_address = ip_config.ipAddress if hasattr(ip_config, 'ipAddress') else 'N/A'
                        subnet_mask = ip_config.subnetMask if hasattr(ip_config, 'subnetMask') else 'N/A'
                        gateway = ip_config.ipV6Config.gateway if hasattr(ip_config, 'ipV6Config') else 'N/A'
                        
                        # Get portgroup
                        portgroup = 'N/A'
                        if hasattr(vnic.spec, 'portgroup'):
                            portgroup = vnic.spec.portgroup
                        
                        vnic_info = {
                            'Host': host.name,
                            'Device': vnic.device,
                            'Portgroup': portgroup,
                            'IP Address': ip_address,
                            'Subnet Mask': subnet_mask,
                            'Gateway': gateway,
                            'MTU': vnic.spec.mtu if hasattr(vnic.spec, 'mtu') else 'N/A',
                            'DHCP Enabled': ip_config.dhcp if hasattr(ip_config, 'dhcp') else 'N/A',
                            'IPv6 Enabled': hasattr(ip_config, 'ipV6Config'),
                            'Connected': vnic.spec.connected if hasattr(vnic.spec, 'connected') else 'N/A'
                        }
                        
                        vnic_data.append(vnic_info)
                
            except Exception as e:
                print(f"Error getting vNIC info for host {host.name}: {str(e)}")
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting vNIC information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no vNICs found
    if not vnic_data:
        vnic_columns = [
            'Host', 'Device', 'Portgroup', 'IP Address', 'Subnet Mask',
            'Gateway', 'MTU', 'DHCP Enabled', 'IPv6 Enabled', 'Connected'
        ]
        return pd.DataFrame(columns=vnic_columns)
    
    return pd.DataFrame(vnic_data)

def get_vhba_info(content):
    """Get information about all host bus adapters"""
    hba_data = []
    
    try:
        # Get all hosts
        container = content.rootFolder
        view_type = [vim.HostSystem]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for host in container_view.view:
            try:
                if hasattr(host.config, 'storageDevice'):
                    for hba in host.config.storageDevice.hostBusAdapter:
                        # Get HBA type
                        hba_type = 'Unknown'
                        if isinstance(hba, vim.host.FibreChannelHba):
                            hba_type = 'Fibre Channel'
                        elif isinstance(hba, vim.host.InternetScsiHba):
                            hba_type = 'iSCSI'
                        elif isinstance(hba, vim.host.SasHba):
                            hba_type = 'SAS'
                        elif isinstance(hba, vim.host.ParaVirtualScsiHba):
                            hba_type = 'ParaVirtual SCSI'
                        
                        # Get WWN/WWPN for FC HBAs
                        wwn = 'N/A'
                        if isinstance(hba, vim.host.FibreChannelHba):
                            wwn = hba.portWorldWideName
                        
                        # Get iSCSI IQN
                        iqn = 'N/A'
                        if isinstance(hba, vim.host.InternetScsiHba):
                            iqn = hba.iScsiName
                        
                        hba_info = {
                            'Host': host.name,
                            'Device': hba.device,
                            'Type': hba_type,
                            'Model': hba.model,
                            'Driver': hba.driver,
                            'Status': hba.status,
                            'WWN/WWPN': wwn,
                            'iSCSI IQN': iqn,
                            'Bus': hba.bus,
                            'PCI': f"{hba.pci:04x}:{hba.pciSlot:02x}"
                        }
                        
                        hba_data.append(hba_info)
                
            except Exception as e:
                print(f"Error getting HBA info for host {host.name}: {str(e)}")
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting HBA information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no HBAs found
    if not hba_data:
        hba_columns = [
            'Host', 'Device', 'Type', 'Model', 'Driver', 'Status',
            'WWN/WWPN', 'iSCSI IQN', 'Bus', 'PCI'
        ]
        return pd.DataFrame(columns=hba_columns)
    
    return pd.DataFrame(hba_data)

def get_vlicense_info(content):
    """Get information about all licenses"""
    license_data = []
    
    try:
        # Get license manager
        license_manager = content.licenseManager
        
        if license_manager:
            # Get all licenses
            for license in license_manager.licenses:
                # Get license properties
                properties = {
                    'Name': license.name,
                    'Total': license.total,
                    'Used': license.used,
                    'Available': license.total - license.used,
                    'Cost Unit': license.costUnit,
                    'Edition Key': license.editionKey,
                    'Key': license.licenseKey,
                    'Labels': ', '.join(license.labels) if hasattr(license, 'labels') else 'N/A',
                    'Expiration': license.expirationDate.replace(tzinfo=None) if hasattr(license, 'expirationDate') and license.expirationDate else 'N/A'
                }
                
                license_data.append(properties)
        
    except Exception as e:
        print(f"Error collecting license information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no licenses found
    if not license_data:
        license_columns = [
            'Name', 'Total', 'Used', 'Available', 'Cost Unit',
            'Edition Key', 'Key', 'Labels', 'Expiration'
        ]
        return pd.DataFrame(columns=license_columns)
    
    return pd.DataFrame(license_data)

def get_vservice_info(content):
    """Get information about all services"""
    service_data = []
    
    try:
        # Get all hosts
        container = content.rootFolder
        view_type = [vim.HostSystem]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for host in container_view.view:
            try:
                if hasattr(host.config, 'service'):
                    for service in host.config.service.service:
                        service_info = {
                            'Host': host.name,
                            'Key': service.key,
                            'Label': service.label,
                            'Required': service.required,
                            'Running': service.running,
                            'Uninstallable': service.uninstallable,
                            'Policy': service.policy,
                            'Source Package': service.sourcePackage if hasattr(service, 'sourcePackage') else 'N/A'
                        }
                        
                        service_data.append(service_info)
                
            except Exception as e:
                print(f"Error getting service info for host {host.name}: {str(e)}")
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting service information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no services found
    if not service_data:
        service_columns = [
            'Host', 'Key', 'Label', 'Required', 'Running',
            'Uninstallable', 'Policy', 'Source Package'
        ]
        return pd.DataFrame(columns=service_columns)
    
    return pd.DataFrame(service_data)

def get_vhealth_info(content):
    """Get information about system health"""
    health_data = []
    
    try:
        # Get all hosts
        container = content.rootFolder
        view_type = [vim.HostSystem]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for host in container_view.view:
            try:
                # Get hardware health
                hardware_health = host.hardware.systemInfo.healthState if hasattr(host.hardware, 'systemInfo') else 'N/A'
                
                # Get storage health
                storage_health = 'N/A'
                if hasattr(host, 'runtime') and hasattr(host.runtime, 'healthSystemRuntime'):
                    storage_health = host.runtime.healthSystemRuntime.storageSystemHealthState
                
                # Get memory health
                memory_health = 'N/A'
                if hasattr(host, 'runtime') and hasattr(host.runtime, 'healthSystemRuntime'):
                    memory_health = host.runtime.healthSystemRuntime.memoryHealthState
                
                # Get CPU health
                cpu_health = 'N/A'
                if hasattr(host, 'runtime') and hasattr(host.runtime, 'healthSystemRuntime'):
                    cpu_health = host.runtime.healthSystemRuntime.cpuHealthState
                
                # Get network health
                network_health = 'N/A'
                if hasattr(host, 'runtime') and hasattr(host.runtime, 'healthSystemRuntime'):
                    network_health = host.runtime.healthSystemRuntime.networkHealthState
                
                health_info = {
                    'Host': host.name,
                    'Hardware Health': hardware_health,
                    'Storage Health': storage_health,
                    'Memory Health': memory_health,
                    'CPU Health': cpu_health,
                    'Network Health': network_health,
                    'Overall Health': host.overallStatus if hasattr(host, 'overallStatus') else 'N/A'
                }
                
                health_data.append(health_info)
                
            except Exception as e:
                print(f"Error getting health info for host {host.name}: {str(e)}")
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting health information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no health data found
    if not health_data:
        health_columns = [
            'Host', 'Hardware Health', 'Storage Health', 'Memory Health',
            'CPU Health', 'Network Health', 'Overall Health'
        ]
        return pd.DataFrame(columns=health_columns)
    
    return pd.DataFrame(health_data)

def get_vresource_info(content):
    """Get information about all resource pools"""
    resource_data = []
    
    try:
        # Get all resource pools
        container = content.rootFolder
        view_type = [vim.ResourcePool]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        for pool in container_view.view:
            try:
                # Get CPU allocation
                cpu_allocation = pool.config.cpuAllocation
                cpu_shares = cpu_allocation.shares.shares if hasattr(cpu_allocation.shares, 'shares') else 'N/A'
                cpu_limit = cpu_allocation.limit if cpu_allocation.limit != -1 else 'Unlimited'
                
                # Get memory allocation
                mem_allocation = pool.config.memoryAllocation
                mem_shares = mem_allocation.shares.shares if hasattr(mem_allocation.shares, 'shares') else 'N/A'
                mem_limit = mem_allocation.limit if mem_allocation.limit != -1 else 'Unlimited'
                
                # Get parent info
                parent = pool.parent
                parent_type = parent.__class__.__name__ if parent else 'N/A'
                parent_name = parent.name if parent else 'N/A'
                
                # Get child pools
                child_pools = len(pool.resourcePool) if hasattr(pool, 'resourcePool') else 0
                
                # Get VMs
                vms = len(pool.vm) if hasattr(pool, 'vm') else 0
                
                resource_info = {
                    'Name': pool.name,
                    'Parent Type': parent_type,
                    'Parent Name': parent_name,
                    'CPU Shares': cpu_shares,
                    'CPU Limit': cpu_limit,
                    'Memory Shares': mem_shares,
                    'Memory Limit': mem_limit,
                    'Child Pools': child_pools,
                    'VMs': vms,
                    'Status': pool.overallStatus if hasattr(pool, 'overallStatus') else 'N/A'
                }
                
                resource_data.append(resource_info)
                
            except Exception as e:
                print(f"Error getting resource pool info for {pool.name}: {str(e)}")
        
        container_view.Destroy()
        
    except Exception as e:
        print(f"Error collecting resource pool information: {str(e)}")
    
    # Create empty DataFrame with correct columns if no resource pools found
    if not resource_data:
        resource_columns = [
            'Name', 'Parent Type', 'Parent Name', 'CPU Shares', 'CPU Limit',
            'Memory Shares', 'Memory Limit', 'Child Pools', 'VMs', 'Status'
        ]
        return pd.DataFrame(columns=resource_columns)
    
    return pd.DataFrame(resource_data)

def get_vm_info(vcenter_host, username, password, port=443, output_dir='output'):
    """
    Connect to vCenter and retrieve VM information
    
    Args:
        vcenter_host (str): vCenter server hostname or IP
        username (str): vCenter username
        password (str): vCenter password
        port (int): vCenter port (default: 443)
        output_dir (str): Directory to save output files (default: 'output')
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")

    # Disable SSL certificate verification
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        # Connect to vCenter
        si = SmartConnect(
            host=vcenter_host,
            user=username,
            pwd=password,
            port=port,
            sslContext=context
        )
        
        # Get content
        content = si.RetrieveContent()
        
        # Get all VMs
        container = content.rootFolder
        view_type = [vim.VirtualMachine]
        recursive = True
        container_view = content.viewManager.CreateContainerView(
            container, view_type, recursive
        )
        
        vms = container_view.view
        
        # Prepare data for CSV
        vm_data = []
        disk_data = []
        
        for vm in vms:
            # Get network adapters
            network_adapters = []
            for device in vm.config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualEthernetCard):
                    network_info = {
                        'label': device.deviceInfo.label,
                        'mac': device.macAddress,
                        'connected': device.connectable.connected,
                        'network_name': device.backing.network.name if hasattr(device.backing, 'network') else 'N/A',
                        'port_group': device.backing.port.portgroupKey if hasattr(device.backing, 'port') else 'N/A'
                    }
                    network_adapters.append(network_info)
            
            # Get disk information
            disk_info = get_disk_info(vm)
            
            # Add disk information to separate list
            for disk in disk_info:
                disk_data.append({
                    'VM Name': vm.name,
                    'Label': disk['label'],
                    'Size (GB)': disk['size_gb'],
                    'Used (GB)': disk['used_gb'],
                    'Datastore': disk['datastore'],
                    'Mode': disk['disk_mode'],
                    'Thin Provisioned': disk['thin_provisioned'],
                    'Controller': disk['controller'],
                    'Unit Number': disk['unit_number'],
                    'Sharing': disk['sharing']
                })
            
            # Get VM tools status
            tools_status = 'N/A'
            if vm.guest:
                tools_status = vm.guest.toolsStatus if hasattr(vm.guest, 'toolsStatus') else 'N/A'
            
            # Get VM hardware version
            hardware_version = vm.config.version if hasattr(vm.config, 'version') else 'N/A'
            
            # Create base VM info
            vm_info = {
                'Name': vm.name,
                'Power State': vm.runtime.powerState,
                'CPU Count': vm.config.hardware.numCPU,
                'Memory (MB)': vm.config.hardware.memoryMB,
                'Guest OS': vm.config.guestFullName if vm.config.guestFullName else 'N/A',
                'IP Address': vm.guest.ipAddress if vm.guest.ipAddress else 'N/A',
                'Host': vm.runtime.host.name if vm.runtime.host else 'N/A',
                'Folder': vm.parent.name if vm.parent else 'N/A',
                'UUID': vm.config.uuid if vm.config.uuid else 'N/A',
                'VMware Tools Status': tools_status,
                'Hardware Version': hardware_version,
                'Firmware': vm.config.firmware if hasattr(vm.config, 'firmware') else 'N/A',
                'Annotation': vm.config.annotation if hasattr(vm.config, 'annotation') else 'N/A',
                'Created': vm.config.createDate.replace(tzinfo=None) if hasattr(vm.config, 'createDate') and vm.config.createDate else 'N/A',
                'Changed': vm.config.changeVersion if hasattr(vm.config, 'changeVersion') else 'N/A',
                'Template': vm.config.template if hasattr(vm.config, 'template') else False,
                'VNC Enabled': vm.config.extraConfig['RemoteDisplay.vnc.enabled'].value if hasattr(vm.config, 'extraConfig') and 'RemoteDisplay.vnc.enabled' in vm.config.extraConfig else 'N/A'
            }
            
            # Add network adapter information
            for i, adapter in enumerate(network_adapters, 1):
                vm_info.update({
                    f'Network Adapter {i} Label': adapter['label'],
                    f'Network Adapter {i} MAC': adapter['mac'],
                    f'Network Adapter {i} Connected': adapter['connected'],
                    f'Network Adapter {i} Network': adapter['network_name'],
                    f'Network Adapter {i} Port Group': adapter['port_group']
                })
            
            vm_data.append(vm_info)
        
        # Create DataFrames
        vm_df = pd.DataFrame(vm_data)
        cluster_df = get_cluster_info(content)
        host_df = get_host_info(content)
        datastore_df = get_datastore_info(content)
        network_df = get_network_info(content)
        disk_df = pd.DataFrame(disk_data)
        vswitch_df = get_vswitch_info(content)
        portgroup_df = get_vportgroup_info(content)
        vnic_df = get_vnic_info(content)
        hba_df = get_vhba_info(content)
        license_df = get_vlicense_info(content)
        service_df = get_vservice_info(content)
        health_df = get_vhealth_info(content)
        resource_df = get_vresource_info(content)
        
        # Create empty DataFrame with correct columns if host_df is empty
        if host_df.empty:
            host_columns = [
                'Name', 'Status', 'Power State', 'CPU Cores', 'CPU Speed (MHz)',
                'Memory (GB)', 'Version', 'Build', 'Vendor', 'Model', 'UUID',
                'Boot Time', 'Maintenance Mode', 'Cluster', 'Network Adapters',
                'Storage Adapters'
            ]
            host_df = pd.DataFrame(columns=host_columns)
        
        # Save to Excel with multiple sheets
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(output_dir, f'vmware_info_{timestamp}.xlsx')
        
        print(f"\nSaving to Excel file: {filename}")  # Debug print
        print("Sheets being created:")  # Debug print
        print("- VM Information")  # Debug print
        print("- Cluster Information")  # Debug print
        print("- Host Information")  # Debug print
        print("- Datastore Information")  # Debug print
        print("- Network Information")  # Debug print
        print("- VM Disk Information")  # Debug print
        print("- vSwitch Information")  # Debug print
        print("- Portgroup Information")  # Debug print
        print("- vNIC Information")  # Debug print
        print("- HBA Information")  # Debug print
        print("- License Information")  # Debug print
        print("- Service Information")  # Debug print
        print("- Health Information")  # Debug print
        print("- Resource Information")  # Debug print
        
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            vm_df.to_excel(writer, sheet_name='VM Information', index=False)
            cluster_df.to_excel(writer, sheet_name='Cluster Information', index=False)
            host_df.to_excel(writer, sheet_name='Host Information', index=False)
            datastore_df.to_excel(writer, sheet_name='Datastore Information', index=False)
            network_df.to_excel(writer, sheet_name='Network Information', index=False)
            disk_df.to_excel(writer, sheet_name='VM Disk Information', index=False)
            vswitch_df.to_excel(writer, sheet_name='vSwitch Information', index=False)
            portgroup_df.to_excel(writer, sheet_name='Portgroup Information', index=False)
            vnic_df.to_excel(writer, sheet_name='vNIC Information', index=False)
            hba_df.to_excel(writer, sheet_name='HBA Information', index=False)
            license_df.to_excel(writer, sheet_name='License Information', index=False)
            service_df.to_excel(writer, sheet_name='Service Information', index=False)
            health_df.to_excel(writer, sheet_name='Health Information', index=False)
            resource_df.to_excel(writer, sheet_name='Resource Information', index=False)
        
        print(f"Information has been saved to {filename}")
        
        # Disconnect from vCenter
        Disconnect(si)
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Try to get credentials from config file first
    config_creds = read_config()
    
    if config_creds:
        vcenter_host, username, password = config_creds
        print("Using credentials from .rv3.conf")
    else:
        # Fall back to command line arguments
        if len(sys.argv) < 4:
            print("Usage: python get_vm_info.py <vcenter_host> <username> <password> [output_dir]")
            print("Or create a .rv3.conf file with the following format:")
            print("[vcenter]")
            print("host = your_vcenter_host")
            print("username = your_username")
            print("password = your_password")
            sys.exit(1)
        
        vcenter_host = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        output_dir = sys.argv[4] if len(sys.argv) > 4 else 'output'
    
    get_vm_info(vcenter_host, username, password, output_dir=output_dir) 