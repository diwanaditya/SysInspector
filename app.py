from flask import Flask, jsonify, render_template_string
import psutil
import platform
import socket
from datetime import datetime, timedelta
import threading
import time
from collections import deque, defaultdict
import json
import subprocess
import os

app = Flask(__name__)

# Enhanced Data Storage
class AdvancedSystemMonitor:
    def __init__(self):
        # Basic metrics
        self.cpu_history = deque(maxlen=120)
        self.memory_history = deque(maxlen=120)
        self.network_upload = deque(maxlen=120)
        self.network_download = deque(maxlen=120)
        self.disk_io = deque(maxlen=120)
        self.cpu_per_core = [deque(maxlen=120) for _ in range(psutil.cpu_count())]
        
        # Advanced metrics
        self.cpu_freq_history = [deque(maxlen=120) for _ in range(psutil.cpu_count())]
        self.cpu_temp_history = deque(maxlen=120)
        self.context_switches_history = deque(maxlen=120)
        self.interrupts_history = deque(maxlen=120)
        self.disk_read_history = deque(maxlen=120)
        self.disk_write_history = deque(maxlen=120)
        self.per_interface_upload = defaultdict(lambda: deque(maxlen=120))
        self.per_interface_download = defaultdict(lambda: deque(maxlen=120))
        
        # State tracking
        self.start_time = time.time()
        self.prev_net = psutil.net_io_counters()
        self.prev_net_per_nic = psutil.net_io_counters(pernic=True)
        self.prev_disk = self.safe_disk_io()
        self.prev_cpu_stats = psutil.cpu_stats()
        self.last_net_time = time.time()
        self.alerts = []
        self.security_events = []
        self.suspicious_processes = []
        
        # Performance cache
        self.cache = {
            'system_info': None,
            'disk_health': None,
            'last_update': 0
        }
        
    def safe_disk_io(self):
        try:
            return psutil.disk_io_counters()
        except:
            return None
    
    def get_cpu_temperature(self):
        """Get CPU temperature with multiple fallback methods for macOS"""
        try:
            # Method 1: psutil sensors (Linux mainly)
            temps = psutil.sensors_temperatures()
            if temps:
                for name in ['coretemp', 'cpu_thermal', 'k10temp', 'zenpower']:
                    if name in temps:
                        temp_list = temps[name]
                        if temp_list:
                            return sum(t.current for t in temp_list) / len(temp_list)
                
                # If no specific sensor, use first available
                first_sensor = list(temps.values())[0]
                if first_sensor:
                    return sum(t.current for t in first_sensor) / len(first_sensor)
        except:
            pass
        
        # Method 2: macOS powermetrics (requires sudo)
        try:
            if platform.system() == 'Darwin':
                result = subprocess.run(
                    ['sudo', 'powermetrics', '--samplers', 'smc', '-i1', '-n1'],
                    capture_output=True, text=True, timeout=3
                )
                for line in result.stdout.split('\n'):
                    if 'CPU die temperature' in line or 'CPU temperature' in line:
                        # Extract temperature value
                        parts = line.split(':')
                        if len(parts) > 1:
                            temp_str = parts[1].strip().split()[0]
                            try:
                                return float(temp_str)
                            except:
                                pass
        except:
            pass
        
        # Method 3: macOS osx-cpu-temp (if installed)
        try:
            if platform.system() == 'Darwin':
                result = subprocess.run(['osx-cpu-temp'], 
                                      capture_output=True, text=True, timeout=1)
                temp_str = result.stdout.strip().replace('°C', '').replace('°', '')
                return float(temp_str)
        except:
            pass
        
        # Method 4: Linux thermal zone
        try:
            if platform.system() == 'Linux':
                result = subprocess.run(['cat', '/sys/class/thermal/thermal_zone0/temp'], 
                                      capture_output=True, text=True, timeout=1)
                return float(result.stdout.strip()) / 1000
        except:
            pass
        
        # Method 5: Estimate from CPU usage (fallback)
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            # Rough estimate: base 40°C + usage factor
            base_temp = 40.0
            temp_per_percent = 0.4
            estimated_temp = base_temp + (cpu_percent * temp_per_percent)
            return min(estimated_temp, 95.0)  # Cap at 95°C
        except:
            pass
        
        return None
    
    def get_disk_smart_data(self):
        """Get SMART disk health data"""
        smart_data = []
        try:
            for partition in psutil.disk_partitions():
                if 'cdrom' in partition.opts or partition.fstype == '':
                    continue
                    
                device = partition.device.replace('/dev/', '')
                health_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'temperature': None,
                    'health_status': 'UNKNOWN',
                    'power_on_hours': None
                }
                
                # Try smartctl (Linux/Unix)
                if platform.system() in ['Linux', 'Darwin']:
                    try:
                        result = subprocess.run(
                            ['smartctl', '-A', '-i', partition.device],
                            capture_output=True, text=True, timeout=2
                        )
                        output = result.stdout
                        
                        # Parse temperature
                        for line in output.split('\n'):
                            if 'Temperature' in line or 'Airflow_Temperature' in line:
                                parts = line.split()
                                for i, part in enumerate(parts):
                                    if part.isdigit() and 20 <= int(part) <= 100:
                                        health_info['temperature'] = int(part)
                                        break
                            elif 'Power_On_Hours' in line:
                                parts = line.split()
                                if len(parts) >= 10:
                                    health_info['power_on_hours'] = parts[9]
                            elif 'SMART overall-health' in line:
                                if 'PASSED' in line:
                                    health_info['health_status'] = 'HEALTHY'
                                else:
                                    health_info['health_status'] = 'WARNING'
                    except:
                        pass
                
                smart_data.append(health_info)
        except:
            pass
        
        return smart_data
    
    def analyze_process_security(self):
        """Analyze processes for suspicious behavior with error handling"""
        suspicious = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 
                                            'memory_percent', 'num_threads']):
                try:
                    info = proc.info
                    risk_score = 0
                    reasons = []
                    
                    # High CPU usage
                    if info.get('cpu_percent', 0) > 80:
                        risk_score += 2
                        reasons.append('High CPU')
                    
                    # High memory usage
                    if info.get('memory_percent', 0) > 50:
                        risk_score += 2
                        reasons.append('High Memory')
                    
                    # Too many threads
                    if info.get('num_threads', 0) > 100:
                        risk_score += 3
                        reasons.append('Excessive Threads')
                    
                    # Try to check network connections (may fail on macOS without sudo)
                    try:
                        connections = proc.connections()
                        if len(connections) > 50:
                            risk_score += 3
                            reasons.append('Many Connections')
                        
                        # Check for external connections
                        external_conns = [c for c in connections 
                                        if c.raddr and not c.raddr.ip.startswith('127.')]
                        if len(external_conns) > 20:
                            risk_score += 2
                            reasons.append('External Connections')
                    except (psutil.AccessDenied, PermissionError, OSError):
                        # Skip connection analysis if not permitted
                        pass
                    
                    if risk_score >= 5:
                        suspicious.append({
                            'pid': info['pid'],
                            'name': info['name'],
                            'risk_score': risk_score,
                            'reasons': ', '.join(reasons),
                            'cpu': info.get('cpu_percent', 0),
                            'memory': info.get('memory_percent', 0)
                        })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"Error in analyze_process_security: {e}")
        
        return sorted(suspicious, key=lambda x: x['risk_score'], reverse=True)[:10]
    
    def update(self):
        """Update all metrics"""
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.5)
        self.cpu_history.append(cpu_percent)
        
        # Per-core CPU and frequency
        cpu_per_core_vals = psutil.cpu_percent(interval=0.1, percpu=True)
        for i, val in enumerate(cpu_per_core_vals):
            if i < len(self.cpu_per_core):
                self.cpu_per_core[i].append(val)
        
        # CPU frequency per core
        try:
            cpu_freqs = psutil.cpu_freq(percpu=True)
            if cpu_freqs:
                for i, freq in enumerate(cpu_freqs):
                    if i < len(self.cpu_freq_history) and freq:
                        self.cpu_freq_history[i].append(freq.current)
        except:
            pass
        
        # CPU temperature
        temp = self.get_cpu_temperature()
        if temp:
            self.cpu_temp_history.append(temp)
        
        # CPU stats (context switches, interrupts)
        try:
            cpu_stats = psutil.cpu_stats()
            if self.prev_cpu_stats:
                ctx_switches = cpu_stats.ctx_switches - self.prev_cpu_stats.ctx_switches
                interrupts = cpu_stats.interrupts - self.prev_cpu_stats.interrupts
                self.context_switches_history.append(ctx_switches)
                self.interrupts_history.append(interrupts)
            self.prev_cpu_stats = cpu_stats
        except:
            pass
        
        # Memory
        mem = psutil.virtual_memory()
        self.memory_history.append(mem.percent)
        
        # Network - global
        try:
            current_net = psutil.net_io_counters()
            time_diff = max(time.time() - getattr(self, 'last_net_time', time.time()), 0.1)
            upload = (current_net.bytes_sent - self.prev_net.bytes_sent) / time_diff / (1024 * 1024)
            download = (current_net.bytes_recv - self.prev_net.bytes_recv) / time_diff / (1024 * 1024)
            self.network_upload.append(max(0, upload))
            self.network_download.append(max(0, download))
            self.prev_net = current_net
            self.last_net_time = time.time()
        except:
            self.network_upload.append(0)
            self.network_download.append(0)
        
        # Network - per interface
        try:
            current_per_nic = psutil.net_io_counters(pernic=True)
            for interface, stats in current_per_nic.items():
                if interface in self.prev_net_per_nic:
                    prev_stats = self.prev_net_per_nic[interface]
                    up = (stats.bytes_sent - prev_stats.bytes_sent) / 1024 / 1024
                    down = (stats.bytes_recv - prev_stats.bytes_recv) / 1024 / 1024
                    self.per_interface_upload[interface].append(max(0, up))
                    self.per_interface_download[interface].append(max(0, down))
            self.prev_net_per_nic = current_per_nic
        except:
            pass
        
        # Disk I/O
        try:
            current_disk = psutil.disk_io_counters()
            if current_disk and self.prev_disk:
                read_mb = (current_disk.read_bytes - self.prev_disk.read_bytes) / (1024 * 1024)
                write_mb = (current_disk.write_bytes - self.prev_disk.write_bytes) / (1024 * 1024)
                self.disk_read_history.append(max(0, read_mb))
                self.disk_write_history.append(max(0, write_mb))
                self.disk_io.append(max(0, (read_mb + write_mb)))
            self.prev_disk = current_disk
        except:
            pass
        
        # Security analysis (every 30 seconds)
        if int(time.time()) % 30 == 0:
            self.suspicious_processes = self.analyze_process_security()
        
        # Check alerts
        self.check_alerts(cpu_percent, mem.percent, temp)
    
    def check_alerts(self, cpu, mem, temp):
        """Enhanced alert system"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if cpu > 90:
            self.alerts.append({
                'type': 'critical',
                'category': 'CPU',
                'message': f'CPU usage critical at {cpu:.1f}%',
                'time': timestamp
            })
        
        if mem > 85:
            self.alerts.append({
                'type': 'warning',
                'category': 'MEMORY',
                'message': f'Memory usage high at {mem:.1f}%',
                'time': timestamp
            })
        
        if temp and temp > 80:
            self.alerts.append({
                'type': 'critical',
                'category': 'THERMAL',
                'message': f'CPU temperature critical at {temp:.1f}°C',
                'time': timestamp
            })
        elif temp and temp > 70:
            self.alerts.append({
                'type': 'warning',
                'category': 'THERMAL',
                'message': f'CPU temperature elevated at {temp:.1f}°C',
                'time': timestamp
            })
        
        # Keep only last 20 alerts
        self.alerts = self.alerts[-20:]

monitor = AdvancedSystemMonitor()

def background_monitor():
    """Background monitoring thread"""
    while True:
        monitor.update()
        time.sleep(1)

thread = threading.Thread(target=background_monitor, daemon=True)
thread.start()

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/metrics')
def get_metrics():
    """Enhanced metrics endpoint with proper error handling"""
    try:
        cpu_per_core = psutil.cpu_percent(percpu=True)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # CPU times breakdown
        cpu_times = psutil.cpu_times()
        cpu_times_dict = {
            'user': cpu_times.user,
            'system': cpu_times.system,
            'idle': cpu_times.idle,
            'iowait': getattr(cpu_times, 'iowait', 0)
        }
        
        # CPU frequency
        try:
            cpu_freq = psutil.cpu_freq()
            cpu_freq_dict = {
                'current': cpu_freq.current if cpu_freq else 0,
                'min': cpu_freq.min if cpu_freq else 0,
                'max': cpu_freq.max if cpu_freq else 0
            }
        except:
            cpu_freq_dict = {'current': 0, 'min': 0, 'max': 0}
        
        # Temperature
        temp = monitor.get_cpu_temperature()
        
        # Calculate health score
        health = 100
        health -= (psutil.cpu_percent() * 0.3)
        health -= (mem.percent * 0.3)
        health -= (disk.percent * 0.2)
        if temp:
            if temp > 80:
                health -= 20
            elif temp > 70:
                health -= 10
        health = max(0, min(100, health))
        
        # Count open ports with error handling
        open_ports_count = 0
        try:
            open_ports_count = len([c for c in psutil.net_connections() if c.status == 'LISTEN'])
        except (psutil.AccessDenied, PermissionError, OSError, RuntimeError):
            # If we can't access connections, try without filtering
            try:
                open_ports_count = len([c for c in psutil.net_connections(kind='inet') if hasattr(c, 'status') and c.status == 'LISTEN'])
            except (psutil.AccessDenied, PermissionError, OSError, RuntimeError):
                open_ports_count = 0
        
        return jsonify({
            'cpu': {
                'percent': psutil.cpu_percent(),
                'cores': cpu_per_core,
                'cores_history': [list(core_hist) for core_hist in monitor.cpu_per_core],
                'history': list(monitor.cpu_history),
                'times': cpu_times_dict,
                'frequency': cpu_freq_dict,
                'freq_history': [list(freq_hist) for freq_hist in monitor.cpu_freq_history],
                'temperature': temp,
                'temp_history': list(monitor.cpu_temp_history),
                'context_switches': list(monitor.context_switches_history),
                'interrupts': list(monitor.interrupts_history)
            },
            'memory': {
                'percent': mem.percent,
                'used': mem.used / (1024**3),
                'total': mem.total / (1024**3),
                'available': mem.available / (1024**3),
                'cached': mem.cached / (1024**3) if hasattr(mem, 'cached') else 0,
                'buffers': mem.buffers / (1024**3) if hasattr(mem, 'buffers') else 0,
                'history': list(monitor.memory_history)
            },
            'disk': {
                'percent': disk.percent,
                'used': disk.used / (1024**3),
                'total': disk.total / (1024**3),
                'free': disk.free / (1024**3),
                'read_history': list(monitor.disk_read_history),
                'write_history': list(monitor.disk_write_history),
                'io_history': list(monitor.disk_io)
            },
            'network': {
                'upload': monitor.network_upload[-1] if monitor.network_upload else 0,
                'download': monitor.network_download[-1] if monitor.network_download else 0,
                'upload_history': list(monitor.network_upload),
                'download_history': list(monitor.network_download),
                'per_interface': {
                    iface: {
                        'upload': list(monitor.per_interface_upload[iface]),
                        'download': list(monitor.per_interface_download[iface])
                    }
                    for iface in monitor.per_interface_upload.keys()
                }
            },
            'system': {
                'uptime': str(timedelta(seconds=int(time.time() - monitor.start_time))),
                'processes': len(list(psutil.process_iter())),
                'health': round(health, 1),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
            },
            'alerts': monitor.alerts,
            'security': {
                'suspicious_processes': monitor.suspicious_processes,
                'open_ports': open_ports_count
            }
        })
    except Exception as e:
        # Log error and return partial data
        print(f"Error in get_metrics: {e}")
        return jsonify({
            'cpu': {'percent': 0, 'cores': [], 'cores_history': [], 'history': [], 'times': {}, 'frequency': {}, 'freq_history': [], 'temperature': None, 'temp_history': [], 'context_switches': [], 'interrupts': []},
            'memory': {'percent': 0, 'used': 0, 'total': 0, 'available': 0, 'cached': 0, 'buffers': 0, 'history': []},
            'disk': {'percent': 0, 'used': 0, 'total': 0, 'free': 0, 'read_history': [], 'write_history': [], 'io_history': []},
            'network': {'upload': 0, 'download': 0, 'upload_history': [], 'download_history': [], 'per_interface': {}},
            'system': {'uptime': '00:00:00', 'processes': 0, 'health': 0, 'boot_time': 'N/A'},
            'alerts': [],
            'security': {'suspicious_processes': [], 'open_ports': 0}
        })

@app.route('/api/processes')
def get_processes():
    """Enhanced process information"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 
                                     'status', 'num_threads', 'create_time']):
        try:
            info = proc.info
            if info['cpu_percent'] is not None:
                # Get I/O counters
                try:
                    io_counters = proc.io_counters()
                    info['io_read'] = io_counters.read_bytes / (1024**2)  # MB
                    info['io_write'] = io_counters.write_bytes / (1024**2)  # MB
                except:
                    info['io_read'] = 0
                    info['io_write'] = 0
                
                # Get context switches
                try:
                    ctx_switches = proc.num_ctx_switches()
                    info['ctx_switches'] = ctx_switches.voluntary + ctx_switches.involuntary
                except:
                    info['ctx_switches'] = 0
                
                processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
    return jsonify(processes[:100])

@app.route('/api/system_info')
def get_system_info():
    """Comprehensive system information"""
    uname = platform.uname()
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    # CPU info
    try:
        cpu_freq = psutil.cpu_freq()
        cpu_freq_info = {
            'current': cpu_freq.current if cpu_freq else 0,
            'min': cpu_freq.min if cpu_freq else 0,
            'max': cpu_freq.max if cpu_freq else 0
        }
    except:
        cpu_freq_info = {'current': 0, 'min': 0, 'max': 0}
    
    # Disk partitions with health
    partitions = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            partitions.append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'total': usage.total / (1024**3),
                'used': usage.used / (1024**3),
                'free': usage.free / (1024**3),
                'percent': usage.percent
            })
        except:
            pass
    
    # Network interfaces
    interfaces = []
    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for interface, addrs in net_if_addrs.items():
            if_info = {
                'name': interface,
                'addresses': []
            }
            
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    if_info['addresses'].append({
                        'type': 'IPv4',
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                elif addr.family == socket.AF_INET6:
                    if_info['addresses'].append({
                        'type': 'IPv6',
                        'address': addr.address
                    })
            
            if interface in net_if_stats:
                stats = net_if_stats[interface]
                if_info['is_up'] = stats.isup
                if_info['speed'] = stats.speed
                if_info['mtu'] = stats.mtu
            
            interfaces.append(if_info)
    except:
        pass
    
    # Users
    users = []
    try:
        for user in psutil.users():
            users.append({
                'name': user.name,
                'terminal': user.terminal,
                'host': user.host,
                'started': datetime.fromtimestamp(user.started).strftime('%Y-%m-%d %H:%M:%S')
            })
    except:
        pass
    
    return jsonify({
        'system': uname.system,
        'node': uname.node,
        'release': uname.release,
        'version': uname.version,
        'machine': uname.machine,
        'processor': uname.processor or platform.processor(),
        'cpu_cores_physical': psutil.cpu_count(logical=False),
        'cpu_cores_logical': psutil.cpu_count(logical=True),
        'cpu_frequency': cpu_freq_info,
        'memory_total': mem.total / (1024**3),
        'swap_total': swap.total / (1024**3),
        'partitions': partitions,
        'interfaces': interfaces,
        'users': users,
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
        'platform': platform.platform()
    })

@app.route('/api/network_connections')
def get_network_connections():
    """Detailed network connections with comprehensive error handling"""
    try:
        connections = []
        try:
            conn_list = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError, OSError, RuntimeError) as e:
            # On macOS without proper privileges, this will fail - return empty list
            print(f"Could not access network connections: {e}")
            return jsonify([])
        
        for conn in conn_list[:200]:
            try:
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                # Get process name
                proc_name = "Unknown"
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                connections.append({
                    'local': local,
                    'remote': remote,
                    'status': conn.status,
                    'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                    'pid': conn.pid or 'N/A',
                    'process': proc_name
                })
            except Exception as e:
                continue
        
        return jsonify(connections)
    except Exception as e:
        print(f"Error in get_network_connections: {e}")
        return jsonify([])

@app.route('/api/disk_health')
def get_disk_health():
    """SMART disk health information"""
    return jsonify(monitor.get_disk_smart_data())

@app.route('/api/security_scan')
def get_security_scan():
    """Security analysis with comprehensive error handling"""
    open_ports = []
    total_connections = 0
    
    try:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    open_ports.append({
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'pid': conn.pid
                    })
        except (psutil.AccessDenied, PermissionError, OSError, RuntimeError) as e:
            # If we can't get connections, leave empty
            print(f"Could not scan ports: {e}")
    except Exception as e:
        print(f"Error scanning ports: {e}")
    
    try:
        try:
            conn_list = list(psutil.net_connections())
            total_connections = len(conn_list)
        except (psutil.AccessDenied, PermissionError, OSError, RuntimeError) as e:
            print(f"Could not count connections: {e}")
            total_connections = 0
    except Exception as e:
        print(f"Error counting connections: {e}")
        total_connections = 0
    
    return jsonify({
        'suspicious_processes': monitor.suspicious_processes,
        'open_ports': open_ports[:50],
        'total_connections': total_connections,
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title> System Inspector</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;500;700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Rajdhani', sans-serif;
            background: #0A0E1A;
            color: #E0E7FF;
            overflow-x: hidden;
        }

        #bg-canvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            opacity: 0.3;
        }

        .container {
            position: relative;
            z-index: 1;
            display: grid;
            grid-template-columns: 250px 1fr;
            grid-template-rows: 80px 1fr 60px;
            height: 100vh;
            gap: 0;
        }

        .sidebar {
            grid-row: 1 / 4;
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(10px);
            border-right: 2px solid rgba(59, 130, 246, 0.3);
            padding: 20px;
            box-shadow: 0 0 30px rgba(59, 130, 246, 0.2);
        }

        .logo {
            font-family: 'Orbitron', sans-serif;
            font-size: 22px;
            font-weight: 900;
            background: linear-gradient(135deg, #3B82F6, #8B5CF6, #06B6D4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 40px;
            text-align: center;
            text-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
        }

        .nav-item {
            padding: 15px 20px;
            margin: 10px 0;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            background: rgba(30, 41, 59, 0.5);
            border: 1px solid rgba(59, 130, 246, 0.2);
            font-size: 13px;
            font-weight: 500;
            letter-spacing: 1px;
        }

        .nav-item:hover, .nav-item.active {
            background: rgba(59, 130, 246, 0.2);
            border-color: #3B82F6;
            box-shadow: 0 0 20px rgba(59, 130, 246, 0.4);
            transform: translateX(5px);
        }

        .header {
            grid-column: 2;
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(10px);
            border-bottom: 2px solid rgba(59, 130, 246, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 30px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        }

        .header-title {
            font-family: 'Orbitron', sans-serif;
            font-size: 26px;
            font-weight: 700;
            color: #3B82F6;
            text-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
        }

        .header-info {
            display: flex;
            gap: 25px;
            font-size: 13px;
        }

        .header-stat {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #10B981;
            animation: pulse 2s infinite;
            box-shadow: 0 0 10px #10B981;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.2); }
        }

        .monitoring-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 700;
            background: rgba(16, 185, 129, 0.2);
            border: 1px solid #10B981;
            color: #10B981;
        }

        .monitoring-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #10B981;
            animation: blink 1.5s infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }

        .data-fresh {
            animation: fadeIn 0.3s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0.5; }
            to { opacity: 1; }
        }

        .card-value {
            font-family: 'Orbitron', sans-serif;
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 10px;
            transition: color 0.3s ease;
        }

        .update-indicator {
            position: absolute;
            top: 10px;
            right: 10px;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #10B981;
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .update-indicator.active {
            opacity: 1;
            animation: ping 1s ease-out;
        }

        @keyframes ping {
            0% {
                transform: scale(1);
                opacity: 1;
            }
            75%, 100% {
                transform: scale(2);
                opacity: 0;
            }
        }

        .main-content {
            grid-column: 2;
            padding: 30px;
            overflow-y: auto;
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .glass-card {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(59, 130, 246, 0.3);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .glass-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.1), transparent);
            transition: left 0.5s;
        }

        .glass-card:hover::before {
            left: 100%;
        }

        .glass-card:hover {
            border-color: #3B82F6;
            box-shadow: 0 8px 32px rgba(59, 130, 246, 0.4);
            transform: translateY(-5px);
        }

        .card-title {
            font-size: 14px;
            font-weight: 500;
            color: #94A3B8;
            margin-bottom: 15px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        .card-value {
            font-family: 'Orbitron', sans-serif;
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .card-unit {
            font-size: 20px;
            color: #64748B;
            margin-left: 5px;
        }

        .card-subtitle {
            font-size: 12px;
            color: #64748B;
        }

        .card-blue .card-value { color: #3B82F6; text-shadow: 0 0 20px rgba(59, 130, 246, 0.5); }
        .card-purple .card-value { color: #8B5CF6; text-shadow: 0 0 20px rgba(139, 92, 246, 0.5); }
        .card-cyan .card-value { color: #06B6D4; text-shadow: 0 0 20px rgba(6, 182, 212, 0.5); }
        .card-green .card-value { color: #10B981; text-shadow: 0 0 20px rgba(16, 185, 129, 0.5); }
        .card-amber .card-value { color: #F59E0B; text-shadow: 0 0 20px rgba(245, 158, 11, 0.5); }
        .card-red .card-value { color: #EF4444; text-shadow: 0 0 20px rgba(239, 68, 68, 0.5); }

        .chart-container {
            grid-column: 1 / -1;
            height: 300px;
            position: relative;
        }

        .chart-wrapper {
            position: relative;
            height: 100%;
        }

        .footer {
            grid-column: 2;
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(10px);
            border-top: 2px solid rgba(59, 130, 246, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 30px;
            font-size: 12px;
            color: #64748B;
        }

        .footer-credit {
            font-family: 'Orbitron', sans-serif;
            color: #3B82F6;
        }

        .alerts-container {
            margin-top: 20px;
            max-height: 200px;
            overflow-y: auto;
        }

        .alert-item {
            background: rgba(239, 68, 68, 0.1);
            border-left: 3px solid #EF4444;
            padding: 10px 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            font-size: 13px;
            display: flex;
            justify-content: space-between;
        }

        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            border-left-color: #F59E0B;
        }

        .alert-thermal {
            background: rgba(239, 68, 68, 0.15);
            border-left-color: #DC2626;
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        .data-table th {
            background: rgba(59, 130, 246, 0.2);
            color: #3B82F6;
            padding: 12px;
            text-align: left;
            font-size: 12px;
            letter-spacing: 1px;
            border-bottom: 2px solid rgba(59, 130, 246, 0.3);
        }

        .data-table td {
            padding: 10px 12px;
            border-bottom: 1px solid rgba(59, 130, 246, 0.1);
            font-size: 13px;
        }

        .data-table tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid rgba(59, 130, 246, 0.1);
        }

        .info-label {
            color: #94A3B8;
            font-weight: 500;
        }

        .info-value {
            color: #E0E7FF;
            font-family: 'Orbitron', sans-serif;
        }

        .core-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .core-card {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            transition: all 0.3s ease;
        }

        .core-card:hover {
            background: rgba(59, 130, 246, 0.15);
            border-color: #3B82F6;
            box-shadow: 0 0 15px rgba(59, 130, 246, 0.3);
        }

        .core-number {
            font-size: 12px;
            color: #94A3B8;
            margin-bottom: 10px;
        }

        .core-value {
            font-family: 'Orbitron', sans-serif;
            font-size: 32px;
            font-weight: 700;
            color: #3B82F6;
            text-shadow: 0 0 15px rgba(59, 130, 246, 0.5);
        }

        .core-freq {
            font-size: 11px;
            color: #64748B;
            margin-top: 5px;
        }

        .risk-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
        }

        .risk-high {
            background: rgba(239, 68, 68, 0.2);
            color: #EF4444;
            border: 1px solid #EF4444;
        }

        .risk-medium {
            background: rgba(245, 158, 11, 0.2);
            color: #F59E0B;
            border: 1px solid #F59E0B;
        }

        .risk-low {
            background: rgba(16, 185, 129, 0.2);
            color: #10B981;
            border: 1px solid #10B981;
        }

        .gauge-container {
            width: 200px;
            height: 200px;
            margin: 20px auto;
            position: relative;
        }

        .temp-indicator {
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 8px;
            display: inline-block;
        }

        .temp-normal {
            background: rgba(16, 185, 129, 0.2);
            color: #10B981;
        }

        .temp-warm {
            background: rgba(245, 158, 11, 0.2);
            color: #F59E0B;
        }

        .temp-hot {
            background: rgba(239, 68, 68, 0.2);
            color: #EF4444;
        }

        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(30, 41, 59, 0.5);
        }

        ::-webkit-scrollbar-thumb {
            background: rgba(59, 130, 246, 0.5);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: rgba(59, 130, 246, 0.8);
        }

        .interface-card {
            background: rgba(59, 130, 246, 0.05);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
        }

        .interface-name {
            font-family: 'Orbitron', sans-serif;
            font-size: 16px;
            color: #3B82F6;
            margin-bottom: 10px;
        }

        .interface-stat {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            font-size: 13px;
        }

        .status-online {
            color: #10B981;
        }

        .status-offline {
            color: #EF4444;
        }
    </style>
</head>
<body>
    <canvas id="bg-canvas"></canvas>
    
    <div class="container">
        <div class="sidebar">
            <div class="logo">System Inspector</div>
            <div class="nav-item active" onclick="showView('overview')">OVERVIEW</div>
            <div class="nav-item" onclick="showView('cpu')">CPU ANALYSIS</div>
            <div class="nav-item" onclick="showView('thermal')">THERMAL MONITOR</div>
            <div class="nav-item" onclick="showView('memory')">MEMORY DEEP</div>
            <div class="nav-item" onclick="showView('disk')">DISK HEALTH</div>
            <div class="nav-item" onclick="showView('network')">NETWORK PRO</div>
            <div class="nav-item" onclick="showView('processes')">PROCESSES</div>
            <div class="nav-item" onclick="showView('security')">SECURITY SCAN</div>
            <div class="nav-item" onclick="showView('system')">SYSTEM INFO</div>
        </div>

        <div class="header">
            <div class="header-title">SYSTEM MONITORING</div>
            <div class="header-info">
                <div class="header-stat">
                    <div class="status-dot"></div>
                    <span>ONLINE</span>
                </div>
                <div class="header-stat">
                    <span>UPTIME <span id="uptime">00:00:00</span></span>
                </div>
                <div class="header-stat">
                    <span>HEALTH <span id="health-score">100</span>%</span>
                </div>
                <div class="header-stat">
                    <span>TEMP <span id="header-temp">--</span>°C</span>
                </div>
            </div>
        </div>

        <div class="main-content" id="main-content"></div>

        <div class="footer">
            <div id="current-time"></div>
            <div class="footer-credit">Developed by Aditya Diwan</div>
        </div>
    </div>

    <script>
        // Three.js Enhanced Background
        const canvas = document.getElementById('bg-canvas');
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ canvas, alpha: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        camera.position.z = 5;

        // Particle system
        const particlesGeometry = new THREE.BufferGeometry();
        const particlesCount = 1500;
        const posArray = new Float32Array(particlesCount * 3);

        for(let i = 0; i < particlesCount * 3; i++) {
            posArray[i] = (Math.random() - 0.5) * 15;
        }

        particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
        const particlesMaterial = new THREE.PointsMaterial({
            size: 0.015,
            color: 0x3B82F6,
            transparent: true,
            opacity: 0.8
        });

        const particlesMesh = new THREE.Points(particlesGeometry, particlesMaterial);
        scene.add(particlesMesh);

        // Multiple geometric shapes
        const shapes = [];
        const geometries = [
            new THREE.IcosahedronGeometry(2, 0),
            new THREE.OctahedronGeometry(1.5, 0),
            new THREE.TetrahedronGeometry(1.2, 0)
        ];

        geometries.forEach((geom, i) => {
            const material = new THREE.MeshBasicMaterial({
                color: [0x3B82F6, 0x8B5CF6, 0x06B6D4][i],
                wireframe: true,
                transparent: true,
                opacity: 0.1
            });
            const mesh = new THREE.Mesh(geom, material);
            mesh.position.set((i - 1) * 3, 0, -2);
            scene.add(mesh);
            shapes.push(mesh);
        });

        function animateBackground() {
            requestAnimationFrame(animateBackground);
            particlesMesh.rotation.y += 0.0008;
            particlesMesh.rotation.x += 0.0005;
            shapes.forEach((shape, i) => {
                shape.rotation.x += 0.002 + (i * 0.001);
                shape.rotation.y += 0.003 + (i * 0.001);
            });
            renderer.render(scene, camera);
        }
        animateBackground();

        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });

        // Charts
        let charts = {};
        
        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(59, 130, 246, 0.1)' },
                    ticks: { color: '#64748B' }
                },
                x: {
                    grid: { color: 'rgba(59, 130, 246, 0.1)' },
                    ticks: { color: '#64748B', display: false }
                }
            },
            animation: {
                duration: 0
            }
        };

        // View Management
        let currentView = 'overview';
        let updateInterval;
        
        function showView(view) {
            currentView = view;
            const navItems = document.querySelectorAll('.nav-item');
            navItems.forEach(item => item.classList.remove('active'));
            event.target.classList.add('active');
            
            const content = document.getElementById('main-content');
            
            // Clear existing charts
            Object.values(charts).forEach(chart => {
                if(chart && typeof chart.destroy === 'function') chart.destroy();
            });
            charts = {};
            
            if(view === 'overview') {
                content.innerHTML = `
                    <div style="margin-bottom: 20px; display: flex; align-items: center; gap: 15px;">
                        <span class="monitoring-badge">
                            <span class="monitoring-dot"></span>
                            LIVE MONITORING
                        </span>
                        <span style="color: #64748B; font-size: 12px;">Updated: <span id="last-update">Just now</span></span>
                    </div>
                    <div class="metrics-grid">
                        <div class="glass-card card-blue">
                            <div class="update-indicator" id="cpu-indicator"></div>
                            <div class="card-title">CPU USAGE</div>
                            <div><span class="card-value data-fresh" id="cpu-percent">0</span><span class="card-unit">%</span></div>
                            <div class="card-subtitle">Real-time processor load</div>
                        </div>
                        <div class="glass-card card-purple">
                            <div class="update-indicator" id="mem-indicator"></div>
                            <div class="card-title">MEMORY USAGE</div>
                            <div><span class="card-value data-fresh" id="mem-percent">0</span><span class="card-unit">%</span></div>
                            <div class="card-subtitle"><span id="mem-used">0</span> GB / <span id="mem-total">0</span> GB</div>
                        </div>
                        <div class="glass-card card-amber">
                            <div class="update-indicator" id="disk-indicator"></div>
                            <div class="card-title">DISK USAGE</div>
                            <div><span class="card-value data-fresh" id="disk-percent">0</span><span class="card-unit">%</span></div>
                            <div class="card-subtitle"><span id="disk-used">0</span> GB / <span id="disk-total">0</span> GB</div>
                        </div>
                        <div class="glass-card card-cyan">
                            <div class="update-indicator" id="net-indicator"></div>
                            <div class="card-title">NETWORK SPEED</div>
                            <div><span class="card-value data-fresh" id="net-speed">0</span><span class="card-unit">MB/s</span></div>
                            <div class="card-subtitle">UP <span id="upload">0</span> | DOWN <span id="download">0</span></div>
                        </div>
                    </div>
                    <div class="metrics-grid">
                        <div class="glass-card chart-container">
                            <div class="card-title">CPU UTILIZATION TIMELINE</div>
                            <div class="chart-wrapper"><canvas id="cpu-chart"></canvas></div>
                        </div>
                        <div class="glass-card chart-container">
                            <div class="card-title">MEMORY USAGE TIMELINE</div>
                            <div class="chart-wrapper"><canvas id="mem-chart"></canvas></div>
                        </div>
                    </div>
                    <div class="glass-card">
                        <div class="card-title">SYSTEM ALERTS</div>
                        <div class="alerts-container" id="alerts-container">
                            <div style="color: #64748B; text-align: center; padding: 20px;">
                                No active alerts - System operating normally
                            </div>
                        </div>
                    </div>
                `;
                initializeChart('cpu-chart', 'CPU %', '#3B82F6');
                initializeChart('mem-chart', 'Memory %', '#8B5CF6');
            } else if(view === 'cpu') {
                content.innerHTML = `
                    <div class="metrics-grid">
                        <div class="glass-card card-blue">
                            <div class="card-title">CPU FREQUENCY</div>
                            <div><span class="card-value" id="cpu-freq">0</span><span class="card-unit">MHz</span></div>
                            <div class="card-subtitle">Current / Max: <span id="cpu-freq-max">0</span> MHz</div>
                        </div>
                        <div class="glass-card card-purple">
                            <div class="card-title">CONTEXT SWITCHES</div>
                            <div><span class="card-value" id="ctx-switches">0</span><span class="card-unit">/s</span></div>
                            <div class="card-subtitle">System context switches per second</div>
                        </div>
                        <div class="glass-card card-cyan">
                            <div class="card-title">INTERRUPTS</div>
                            <div><span class="card-value" id="interrupts">0</span><span class="card-unit">/s</span></div>
                            <div class="card-subtitle">Hardware interrupts per second</div>
                        </div>
                    </div>
                    <div class="glass-card">
                        <div class="card-title">PER-CORE UTILIZATION & FREQUENCY</div>
                        <div class="core-grid" id="cores-grid"></div>
                    </div>
                    <div class="glass-card chart-container" style="margin-top: 20px;">
                        <div class="card-title">MULTI-CORE PERFORMANCE TIMELINE</div>
                        <div class="chart-wrapper"><canvas id="cores-chart"></canvas></div>
                    </div>
                    <div class="glass-card chart-container" style="margin-top: 20px;">
                        <div class="card-title">CPU MODES BREAKDOWN</div>
                        <div class="chart-wrapper"><canvas id="cpu-times-chart"></canvas></div>
                    </div>
                `;
                initializeMultiLineChart('cores-chart');
                initializeCPUTimesChart();
            } else if(view === 'thermal') {
                content.innerHTML = `
                    <div class="metrics-grid">
                        <div class="glass-card card-red">
                            <div class="card-title">CPU TEMPERATURE</div>
                            <div><span class="card-value" id="cpu-temp">--</span><span class="card-unit">°C</span></div>
                            <div class="card-subtitle" id="temp-status">Monitoring...</div>
                        </div>
                    </div>
                    <div class="glass-card chart-container">
                        <div class="card-title">TEMPERATURE HISTORY</div>
                        <div class="chart-wrapper"><canvas id="temp-chart"></canvas></div>
                    </div>
                    <div class="glass-card" style="margin-top: 20px;">
                        <div class="card-title">THERMAL ANALYSIS</div>
                        <div id="thermal-analysis" style="padding: 20px;"></div>
                    </div>
                `;
                initializeChart('temp-chart', 'Temperature °C', '#EF4444');
            } else if(view === 'memory') {
                content.innerHTML = `
                    <div class="metrics-grid">
                        <div class="glass-card card-purple">
                            <div class="card-title">MEMORY USAGE</div>
                            <div><span class="card-value" id="mem-percent-2">0</span><span class="card-unit">%</span></div>
                            <div class="card-subtitle">Used memory percentage</div>
                        </div>
                        <div class="glass-card card-cyan">
                            <div class="card-title">USED MEMORY</div>
                            <div><span class="card-value" id="mem-used-2">0</span><span class="card-unit">GB</span></div>
                            <div class="card-subtitle">Currently allocated</div>
                        </div>
                        <div class="glass-card card-green">
                            <div class="card-title">AVAILABLE MEMORY</div>
                            <div><span class="card-value" id="mem-avail">0</span><span class="card-unit">GB</span></div>
                            <div class="card-subtitle">Free for allocation</div>
                        </div>
                        <div class="glass-card card-blue">
                            <div class="card-title">CACHED MEMORY</div>
                            <div><span class="card-value" id="mem-cached">0</span><span class="card-unit">GB</span></div>
                            <div class="card-subtitle">System cache</div>
                        </div>
                    </div>
                    <div class="glass-card chart-container">
                        <div class="card-title">MEMORY USAGE HISTORY</div>
                        <div class="chart-wrapper"><canvas id="mem-chart-2"></canvas></div>
                    </div>
                `;
                initializeChart('mem-chart-2', 'Memory %', '#8B5CF6');
            } else if(view === 'disk') {
                content.innerHTML = `
                    <div class="metrics-grid">
                        <div class="glass-card card-amber">
                            <div class="card-title">DISK READ</div>
                            <div><span class="card-value" id="disk-read">0</span><span class="card-unit">MB/s</span></div>
                            <div class="card-subtitle">Read throughput</div>
                        </div>
                        <div class="glass-card card-red">
                            <div class="card-title">DISK WRITE</div>
                            <div><span class="card-value" id="disk-write">0</span><span class="card-unit">MB/s</span></div>
                            <div class="card-subtitle">Write throughput</div>
                        </div>
                    </div>
                    <div class="glass-card chart-container">
                        <div class="card-title">DISK I/O PERFORMANCE</div>
                        <div class="chart-wrapper"><canvas id="disk-io-chart"></canvas></div>
                    </div>
                    <div class="glass-card" style="margin-top: 20px;">
                        <div class="card-title">SMART DISK HEALTH STATUS</div>
                        <div id="disk-health-content" style="padding: 15px;"></div>
                    </div>
                `;
                initializeMultiLineChart('disk-io-chart');
                loadDiskHealth();
            } else if(view === 'network') {
                content.innerHTML = `
                    <div class="metrics-grid">
                        <div class="glass-card card-cyan">
                            <div class="card-title">UPLOAD SPEED</div>
                            <div><span class="card-value" id="upload-2">0</span><span class="card-unit">MB/s</span></div>
                            <div class="card-subtitle">Current upload rate</div>
                        </div>
                        <div class="glass-card card-blue">
                            <div class="card-title">DOWNLOAD SPEED</div>
                            <div><span class="card-value" id="download-2">0</span><span class="card-unit">MB/s</span></div>
                            <div class="card-subtitle">Current download rate</div>
                        </div>
                    </div>
                    <div class="glass-card chart-container">
                        <div class="card-title">NETWORK THROUGHPUT TIMELINE</div>
                        <div class="chart-wrapper"><canvas id="net-chart"></canvas></div>
                    </div>
                    <div class="glass-card" style="margin-top: 20px;">
                        <div class="card-title">NETWORK INTERFACES</div>
                        <div id="interfaces-content"></div>
                    </div>
                    <div class="glass-card" style="margin-top: 20px;">
                        <div class="card-title">ACTIVE NETWORK CONNECTIONS</div>
                        <div style="overflow-x: auto;">
                            <table class="data-table" id="connections-table">
                                <thead>
                                    <tr>
                                        <th>LOCAL ADDRESS</th>
                                        <th>REMOTE ADDRESS</th>
                                        <th>STATUS</th>
                                        <th>TYPE</th>
                                        <th>PROCESS</th>
                                    </tr>
                                </thead>
                                <tbody id="connections-tbody"></tbody>
                            </table>
                        </div>
                    </div>
                `;
                initializeMultiLineChart('net-chart');
            } else if(view === 'processes') {
                content.innerHTML = `
                    <div class="glass-card">
                        <div class="card-title">TOP PROCESSES BY CPU USAGE</div>
                        <div style="overflow-x: auto;">
                            <table class="data-table" id="processes-table">
                                <thead>
                                    <tr>
                                        <th>PID</th>
                                        <th>NAME</th>
                                        <th>CPU %</th>
                                        <th>MEMORY %</th>
                                        <th>THREADS</th>
                                        <th>DISK I/O</th>
                                        <th>CTX SWITCHES</th>
                                        <th>STATUS</th>
                                    </tr>
                                </thead>
                                <tbody id="processes-tbody"></tbody>
                            </table>
                        </div>
                    </div>
                `;
            } else if(view === 'security') {
                content.innerHTML = `
                    <div class="metrics-grid">
                        <div class="glass-card card-red">
                            <div class="card-title">SUSPICIOUS PROCESSES</div>
                            <div><span class="card-value" id="suspicious-count">0</span><span class="card-unit"></span></div>
                            <div class="card-subtitle">Processes with high risk score</div>
                        </div>
                        <div class="glass-card card-amber">
                            <div class="card-title">OPEN PORTS</div>
                            <div><span class="card-value" id="open-ports">0</span><span class="card-unit"></span></div>
                            <div class="card-subtitle">Listening network ports</div>
                        </div>
                    </div>
                    <div class="glass-card">
                        <div class="card-title">SUSPICIOUS PROCESS ANALYSIS</div>
                        <div style="overflow-x: auto;">
                            <table class="data-table" id="security-table">
                                <thead>
                                    <tr>
                                        <th>RISK LEVEL</th>
                                        <th>PID</th>
                                        <th>PROCESS NAME</th>
                                        <th>CPU %</th>
                                        <th>MEMORY %</th>
                                        <th>REASONS</th>
                                    </tr>
                                </thead>
                                <tbody id="security-tbody"></tbody>
                            </table>
                        </div>
                    </div>
                    <div class="glass-card" style="margin-top: 20px;">
                        <div class="card-title">OPEN PORTS SCAN</div>
                        <div style="overflow-x: auto;">
                            <table class="data-table" id="ports-table">
                                <thead>
                                    <tr>
                                        <th>PORT</th>
                                        <th>ADDRESS</th>
                                        <th>TYPE</th>
                                        <th>PID</th>
                                    </tr>
                                </thead>
                                <tbody id="ports-tbody"></tbody>
                            </table>
                        </div>
                    </div>
                `;
            } else if(view === 'system') {
                content.innerHTML = `
                    <div class="glass-card">
                        <div class="card-title">SYSTEM INFORMATION</div>
                        <div id="system-info-content"></div>
                    </div>
                `;
                loadSystemInfo();
            }
            
            updateData();
        }

        function initializeChart(canvasId, label, color) {
            const canvas = document.getElementById(canvasId);
            if(!canvas) return;
            
            charts[canvasId] = new Chart(canvas, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: label,
                        data: [],
                        borderColor: color,
                        backgroundColor: color.replace(')', ', 0.1)').replace('rgb', 'rgba'),
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: chartOptions
            });
        }

        function initializeMultiLineChart(canvasId) {
            const canvas = document.getElementById(canvasId);
            if(!canvas) return;
            
            charts[canvasId] = new Chart(canvas, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: []
                },
                options: {
                    ...chartOptions,
                    plugins: { 
                        legend: { 
                            display: true,
                            labels: { color: '#94A3B8', font: { size: 11 } }
                        } 
                    }
                }
            });
        }

        function initializeCPUTimesChart() {
            const canvas = document.getElementById('cpu-times-chart');
            if(!canvas) return;
            
            charts['cpu-times-chart'] = new Chart(canvas, {
                type: 'doughnut',
                data: {
                    labels: ['User', 'System', 'Idle', 'I/O Wait'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            'rgba(59, 130, 246, 0.8)',
                            'rgba(139, 92, 246, 0.8)',
                            'rgba(16, 185, 129, 0.8)',
                            'rgba(245, 158, 11, 0.8)'
                        ],
                        borderColor: [
                            '#3B82F6',
                            '#8B5CF6',
                            '#10B981',
                            '#F59E0B'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: true,
                            position: 'right',
                            labels: { 
                                color: '#94A3B8',
                                font: { size: 12 },
                                padding: 15
                            }
                        }
                    }
                }
            });
        }

        function updateChart(chartId, data, labels) {
            if(charts[chartId] && data.length > 0) {
                charts[chartId].data.labels = labels || data.map((_, i) => i);
                charts[chartId].data.datasets[0].data = data;
                charts[chartId].update('none');
            }
        }

        function updateMultiLineChart(chartId, datasets, labels) {
            if(charts[chartId] && datasets.length > 0) {
                charts[chartId].data.labels = labels || datasets[0].data.map((_, i) => i);
                charts[chartId].data.datasets = datasets;
                charts[chartId].update('none');
            }
        }

        async function updateData() {
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();

                // Update last update time
                const lastUpdate = document.getElementById('last-update');
                if(lastUpdate) {
                    lastUpdate.textContent = 'Just now';
                }

                // Trigger update indicators
                ['cpu-indicator', 'mem-indicator', 'disk-indicator', 'net-indicator'].forEach(id => {
                    const indicator = document.getElementById(id);
                    if(indicator) {
                        indicator.classList.add('active');
                        setTimeout(() => indicator.classList.remove('active'), 1000);
                    }
                });

                // Update header
                document.getElementById('uptime').textContent = data.system.uptime;
                document.getElementById('health-score').textContent = data.system.health;
                
                const headerTemp = document.getElementById('header-temp');
                if(data.cpu.temperature) {
                    headerTemp.textContent = data.cpu.temperature.toFixed(1);
                    headerTemp.style.color = data.cpu.temperature > 70 ? '#EF4444' : 
                                           data.cpu.temperature > 60 ? '#F59E0B' : '#10B981';
                } else {
                    headerTemp.textContent = '--';
                }

                if(currentView === 'overview') {
                    document.getElementById('cpu-percent').textContent = data.cpu.percent.toFixed(1);
                    document.getElementById('mem-percent').textContent = data.memory.percent.toFixed(1);
                    document.getElementById('mem-used').textContent = data.memory.used.toFixed(1);
                    document.getElementById('mem-total').textContent = data.memory.total.toFixed(1);
                    document.getElementById('disk-percent').textContent = data.disk.percent.toFixed(1);
                    document.getElementById('disk-used').textContent = data.disk.used.toFixed(1);
                    document.getElementById('disk-total').textContent = data.disk.total.toFixed(1);
                    document.getElementById('net-speed').textContent = (data.network.upload + data.network.download).toFixed(2);
                    document.getElementById('upload').textContent = data.network.upload.toFixed(2);
                    document.getElementById('download').textContent = data.network.download.toFixed(2);

                    updateChart('cpu-chart', data.cpu.history);
                    updateChart('mem-chart', data.memory.history);

                    // Alerts
                    const alertsContainer = document.getElementById('alerts-container');
                    if(data.alerts.length > 0) {
                        alertsContainer.innerHTML = data.alerts.map(alert => `
                            <div class="alert-item ${alert.type === 'warning' ? 'alert-warning' : ''} ${alert.category === 'THERMAL' ? 'alert-thermal' : ''}">
                                <span>[${alert.time}] <strong>${alert.category}</strong>: ${alert.message}</span>
                                <span class="risk-badge ${alert.type === 'critical' ? 'risk-high' : 'risk-medium'}">${alert.type.toUpperCase()}</span>
                            </div>
                        `).join('');
                    } else {
                        alertsContainer.innerHTML = `
                            <div style="color: #64748B; text-align: center; padding: 20px;">
                                No active alerts - System operating normally
                            </div>
                        `;
                    }
                } else if(currentView === 'cpu') {
                    document.getElementById('cpu-freq').textContent = data.cpu.frequency.current.toFixed(0);
                    document.getElementById('cpu-freq-max').textContent = data.cpu.frequency.max.toFixed(0);
                    
                    if(data.cpu.context_switches.length > 0) {
                        document.getElementById('ctx-switches').textContent = 
                            data.cpu.context_switches[data.cpu.context_switches.length - 1].toFixed(0);
                    }
                    
                    if(data.cpu.interrupts.length > 0) {
                        document.getElementById('interrupts').textContent = 
                            data.cpu.interrupts[data.cpu.interrupts.length - 1].toFixed(0);
                    }

                    // Per-core display
                    const coresGrid = document.getElementById('cores-grid');
                    if(coresGrid) {
                        coresGrid.innerHTML = data.cpu.cores.map((core, i) => {
                            const freq = data.cpu.freq_history[i] && data.cpu.freq_history[i].length > 0 ?
                                data.cpu.freq_history[i][data.cpu.freq_history[i].length - 1] : 0;
                            return `
                                <div class="core-card">
                                    <div class="core-number">CORE ${i}</div>
                                    <div class="core-value">${core.toFixed(1)}%</div>
                                    <div class="core-freq">${freq.toFixed(0)} MHz</div>
                                </div>
                            `;
                        }).join('');
                    }

                    // Multi-core chart
                    if(data.cpu.cores_history.length > 0) {
                        const colors = ['#3B82F6', '#8B5CF6', '#06B6D4', '#10B981', '#F59E0B', '#EF4444', '#EC4899', '#6366F1'];
                        const datasets = data.cpu.cores_history.map((coreData, i) => ({
                            label: `Core ${i}`,
                            data: coreData,
                            borderColor: colors[i % colors.length],
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        }));
                        updateMultiLineChart('cores-chart', datasets);
                    }

                    // CPU times chart (doughnut)
                    if(charts['cpu-times-chart'] && data.cpu.times) {
                        const total = data.cpu.times.user + data.cpu.times.system + 
                                     data.cpu.times.idle + data.cpu.times.iowait;
                        if(total > 0) {
                            charts['cpu-times-chart'].data.datasets[0].data = [
                                ((data.cpu.times.user / total) * 100).toFixed(1),
                                ((data.cpu.times.system / total) * 100).toFixed(1),
                                ((data.cpu.times.idle / total) * 100).toFixed(1),
                                ((data.cpu.times.iowait / total) * 100).toFixed(1)
                            ];
                            charts['cpu-times-chart'].update('none');
                        }
                    }
                } else if(currentView === 'thermal') {
                    if(data.cpu.temperature) {
                        document.getElementById('cpu-temp').textContent = data.cpu.temperature.toFixed(1);
                        
                        const tempStatus = document.getElementById('temp-status');
                        if(data.cpu.temperature > 80) {
                            tempStatus.innerHTML = '<span class="temp-indicator temp-hot">CRITICAL - Check Cooling</span>';
                        } else if(data.cpu.temperature > 70) {
                            tempStatus.innerHTML = '<span class="temp-indicator temp-warm">ELEVATED - Monitor Closely</span>';
                        } else {
                            tempStatus.innerHTML = '<span class="temp-indicator temp-normal">NORMAL - Operating Safely</span>';
                        }

                        // Thermal analysis
                        const analysis = document.getElementById('thermal-analysis');
                        if(analysis) {
                            const avgTemp = data.cpu.temp_history.reduce((a, b) => a + b, 0) / data.cpu.temp_history.length;
                            const maxTemp = Math.max(...data.cpu.temp_history);
                            const minTemp = Math.min(...data.cpu.temp_history);
                            
                            analysis.innerHTML = `
                                <div class="info-row">
                                    <div class="info-label">CURRENT TEMPERATURE</div>
                                    <div class="info-value">${data.cpu.temperature.toFixed(1)}°C</div>
                                </div>
                                <div class="info-row">
                                    <div class="info-label">AVERAGE TEMPERATURE</div>
                                    <div class="info-value">${avgTemp.toFixed(1)}°C</div>
                                </div>
                                <div class="info-row">
                                    <div class="info-label">MAXIMUM RECORDED</div>
                                    <div class="info-value">${maxTemp.toFixed(1)}°C</div>
                                </div>
                                <div class="info-row">
                                    <div class="info-label">MINIMUM RECORDED</div>
                                    <div class="info-value">${minTemp.toFixed(1)}°C</div>
                                </div>
                                <div class="info-row">
                                    <div class="info-label">THERMAL MARGIN</div>
                                    <div class="info-value">${(100 - data.cpu.temperature).toFixed(1)}°C</div>
                                </div>
                            `;
                        }
                    }

                    updateChart('temp-chart', data.cpu.temp_history);
                } else if(currentView === 'memory') {
                    document.getElementById('mem-percent-2').textContent = data.memory.percent.toFixed(1);
                    document.getElementById('mem-used-2').textContent = data.memory.used.toFixed(1);
                    document.getElementById('mem-avail').textContent = data.memory.available.toFixed(1);
                    document.getElementById('mem-cached').textContent = data.memory.cached.toFixed(1);

                    updateChart('mem-chart-2', data.memory.history);
                } else if(currentView === 'disk') {
                    if(data.disk.read_history.length > 0) {
                        document.getElementById('disk-read').textContent = 
                            data.disk.read_history[data.disk.read_history.length - 1].toFixed(2);
                    }
                    if(data.disk.write_history.length > 0) {
                        document.getElementById('disk-write').textContent = 
                            data.disk.write_history[data.disk.write_history.length - 1].toFixed(2);
                    }

                    // Disk I/O chart
                    const datasets = [
                        {
                            label: 'Read MB/s',
                            data: data.disk.read_history,
                            borderColor: '#F59E0B',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        },
                        {
                            label: 'Write MB/s',
                            data: data.disk.write_history,
                            borderColor: '#EF4444',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        }
                    ];
                    updateMultiLineChart('disk-io-chart', datasets);
                } else if(currentView === 'network') {
                    document.getElementById('upload-2').textContent = data.network.upload.toFixed(2);
                    document.getElementById('download-2').textContent = data.network.download.toFixed(2);

                    // Network chart
                    const datasets = [
                        {
                            label: 'Upload MB/s',
                            data: data.network.upload_history,
                            borderColor: '#06B6D4',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        },
                        {
                            label: 'Download MB/s',
                            data: data.network.download_history,
                            borderColor: '#3B82F6',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.4
                        }
                    ];
                    updateMultiLineChart('net-chart', datasets);

                    // Update connections periodically
                    if(Math.random() < 0.2) {
                        loadNetworkConnections();
                    }
                } else if(currentView === 'processes') {
                    loadProcesses();
                } else if(currentView === 'security') {
                    loadSecurityScan();
                }
            } catch(error) {
                console.error('Error fetching metrics:', error);
            }
        }

        async function loadProcesses() {
            try {
                const response = await fetch('/api/processes');
                const processes = await response.json();
                
                const tbody = document.getElementById('processes-tbody');
                if(tbody) {
                    tbody.innerHTML = processes.slice(0, 50).map(proc => `
                        <tr>
                            <td>${proc.pid}</td>
                            <td>${proc.name}</td>
                            <td>${(proc.cpu_percent || 0).toFixed(1)}%</td>
                            <td>${(proc.memory_percent || 0).toFixed(1)}%</td>
                            <td>${proc.num_threads || 0}</td>
                            <td>${(proc.io_read + proc.io_write).toFixed(1)} MB</td>
                            <td>${proc.ctx_switches || 0}</td>
                            <td>${proc.status || 'unknown'}</td>
                        </tr>
                    `).join('');
                }
            } catch(error) {
                console.error('Error loading processes:', error);
            }
        }

        async function loadNetworkConnections() {
            try {
                const response = await fetch('/api/network_connections');
                const connections = await response.json();
                
                const tbody = document.getElementById('connections-tbody');
                if(tbody) {
                    tbody.innerHTML = connections.slice(0, 50).map(conn => `
                        <tr>
                            <td>${conn.local}</td>
                            <td>${conn.remote}</td>
                            <td>${conn.status}</td>
                            <td>${conn.type}</td>
                            <td>${conn.process}</td>
                        </tr>
                    `).join('');
                }
            } catch(error) {
                console.error('Error loading connections:', error);
            }
        }

        async function loadSystemInfo() {
            try {
                const response = await fetch('/api/system_info');
                const info = await response.json();
                
                const content = document.getElementById('system-info-content');
                if(content) {
                    content.innerHTML = `
                        <div class="info-row">
                            <div class="info-label">SYSTEM</div>
                            <div class="info-value">${info.system}</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">PLATFORM</div>
                            <div class="info-value">${info.platform}</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">NODE NAME</div>
                            <div class="info-value">${info.node}</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">RELEASE</div>
                            <div class="info-value">${info.release}</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">MACHINE</div>
                            <div class="info-value">${info.machine}</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">PROCESSOR</div>
                            <div class="info-value">${info.processor}</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">PHYSICAL CORES</div>
                            <div class="info-value">${info.cpu_cores_physical}</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">LOGICAL CORES</div>
                            <div class="info-value">${info.cpu_cores_logical}</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">CPU FREQUENCY</div>
                            <div class="info-value">${info.cpu_frequency.current.toFixed(0)} MHz (Max: ${info.cpu_frequency.max.toFixed(0)} MHz)</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">TOTAL MEMORY</div>
                            <div class="info-value">${info.memory_total.toFixed(2)} GB</div>
                        </div>
                        <div class="info-row">
                            <div class="info-label">BOOT TIME</div>
                            <div class="info-value">${info.boot_time}</div>
                        </div>
                        ${info.users.length > 0 ? `
                            <div style="margin-top: 30px;">
                                <div class="card-title">LOGGED IN USERS</div>
                                ${info.users.map(u => `
                                    <div class="info-row">
                                        <div class="info-label">${u.name} @ ${u.terminal}</div>
                                        <div class="info-value">${u.started}</div>
                                    </div>
                                `).join('')}
                            </div>
                        ` : ''}
                        <div style="margin-top: 30px;">
                            <div class="card-title">DISK PARTITIONS</div>
                            ${info.partitions.map(p => `
                                <div style="background: rgba(59, 130, 246, 0.05); padding: 15px; margin: 10px 0; border-radius: 8px; border: 1px solid rgba(59, 130, 246, 0.2);">
                                    <div class="info-row" style="border: none;">
                                        <div class="info-label">DEVICE</div>
                                        <div class="info-value">${p.device}</div>
                                    </div>
                                    <div class="info-row" style="border: none;">
                                        <div class="info-label">MOUNTPOINT</div>
                                        <div class="info-value">${p.mountpoint}</div>
                                    </div>
                                    <div class="info-row" style="border: none;">
                                        <div class="info-label">FILESYSTEM</div>
                                        <div class="info-value">${p.fstype}</div>
                                    </div>
                                    <div class="info-row" style="border: none;">
                                        <div class="info-label">USAGE</div>
                                        <div class="info-value">${p.used.toFixed(2)} GB / ${p.total.toFixed(2)} GB (${p.percent}%)</div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                        <div style="margin-top: 30px;">
                            <div class="card-title">NETWORK INTERFACES</div>
                            ${info.interfaces.map(iface => `
                                <div class="interface-card">
                                    <div class="interface-name">${iface.name} ${iface.is_up ? '<span class="status-online">● ONLINE</span>' : '<span class="status-offline">● OFFLINE</span>'}</div>
                                    ${iface.speed ? `<div class="interface-stat"><span>Speed</span><span>${iface.speed} Mbps</span></div>` : ''}
                                    ${iface.mtu ? `<div class="interface-stat"><span>MTU</span><span>${iface.mtu}</span></div>` : ''}
                                    ${iface.addresses.map(addr => `
                                        <div class="interface-stat"><span>${addr.type}</span><span>${addr.address}</span></div>
                                    `).join('')}
                                </div>
                            `).join('')}
                        </div>
                    `;
                }
            } catch(error) {
                console.error('Error loading system info:', error);
            }
        }

        async function loadDiskHealth() {
            try {
                const response = await fetch('/api/disk_health');
                const health = await response.json();
                
                const content = document.getElementById('disk-health-content');
                if(content) {
                    if(health.length > 0) {
                        content.innerHTML = health.map(disk => `
                            <div style="background: rgba(59, 130, 246, 0.05); padding: 15px; margin: 10px 0; border-radius: 8px; border: 1px solid rgba(59, 130, 246, 0.2);">
                                <div class="info-row" style="border: none;">
                                    <div class="info-label">DEVICE</div>
                                    <div class="info-value">${disk.device}</div>
                                </div>
                                <div class="info-row" style="border: none;">
                                    <div class="info-label">MOUNTPOINT</div>
                                    <div class="info-value">${disk.mountpoint}</div>
                                </div>
                                <div class="info-row" style="border: none;">
                                    <div class="info-label">HEALTH STATUS</div>
                                    <div class="info-value">
                                        <span class="risk-badge ${disk.health_status === 'HEALTHY' ? 'risk-low' : disk.health_status === 'WARNING' ? 'risk-medium' : 'risk-high'}">
                                            ${disk.health_status}
                                        </span>
                                    </div>
                                </div>
                                ${disk.temperature ? `
                                    <div class="info-row" style="border: none;">
                                        <div class="info-label">TEMPERATURE</div>
                                        <div class="info-value">${disk.temperature}°C</div>
                                    </div>
                                ` : ''}
                                ${disk.power_on_hours ? `
                                    <div class="info-row" style="border: none;">
                                        <div class="info-label">POWER ON HOURS</div>
                                        <div class="info-value">${disk.power_on_hours}</div>
                                    </div>
                                ` : ''}
                            </div>
                        `).join('');
                    } else {
                        content.innerHTML = '<div style="color: #64748B; text-align: center; padding: 20px;">SMART data not available. Requires smartctl and sudo privileges.</div>';
                    }
                }
            } catch(error) {
                console.error('Error loading disk health:', error);
            }
        }

        async function loadSecurityScan() {
            try {
                const response = await fetch('/api/security_scan');
                const security = await response.json();
                
                document.getElementById('suspicious-count').textContent = security.suspicious_processes.length;
                document.getElementById('open-ports').textContent = security.open_ports.length;

                // Suspicious processes
                const securityTbody = document.getElementById('security-tbody');
                if(securityTbody) {
                    securityTbody.innerHTML = security.suspicious_processes.map(proc => `
                        <tr>
                            <td>
                                <span class="risk-badge ${proc.risk_score >= 7 ? 'risk-high' : proc.risk_score >= 5 ? 'risk-medium' : 'risk-low'}">
                                    ${proc.risk_score >= 7 ? 'HIGH' : proc.risk_score >= 5 ? 'MEDIUM' : 'LOW'}
                                </span>
                            </td>
                            <td>${proc.pid}</td>
                            <td>${proc.name}</td>
                            <td>${proc.cpu.toFixed(1)}%</td>
                            <td>${proc.memory.toFixed(1)}%</td>
                            <td>${proc.reasons}</td>
                        </tr>
                    `).join('');
                }

                // Open ports
                const portsTbody = document.getElementById('ports-tbody');
                if(portsTbody) {
                    portsTbody.innerHTML = security.open_ports.map(port => `
                        <tr>
                            <td>${port.port}</td>
                            <td>${port.address}</td>
                            <td>${port.type}</td>
                            <td>${port.pid || 'N/A'}</td>
                        </tr>
                    `).join('');
                }
            } catch(error) {
                console.error('Error loading security scan:', error);
            }
        }

        function updateClock() {
            const now = new Date();
            document.getElementById('current-time').textContent = now.toLocaleTimeString();
        }

        // Initialize
        showView('overview');
        setInterval(updateData, 1000);
        updateClock();
        setInterval(updateClock, 1000);
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    print("=" * 70)
    print(" System Inspector ".center(70))
    print("=" * 70)
    print("\n Advanced System Monitoring with Deep Analytics")
    print("\n Features:")
    print("   • Real-time CPU deep analysis (per-core frequency, context switches)")
    print("   • Thermal monitoring with temperature tracking")
    print("   • Memory forensics with cache/buffer analysis")
    print("   • SMART disk health monitoring")
    print("   • Per-interface network analysis")
    print("   • Process security analysis with risk scoring")
    print("   • Advanced 3D visualizations")
    print("\n Server starting at: http://localhost:5000")
    print("=" * 70)
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
