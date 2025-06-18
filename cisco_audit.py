import threading
import queue
import csv
import logging
from getpass import getpass
from datetime import datetime
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from tqdm import tqdm

# --- Configuration ---
NUM_THREADS = 10  # Adjust based on your system's capability and network latency
DEVICE_FILE = 'devices.txt'
TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
LOG_FILE = f"network_audit_{TIMESTAMP}.log"
CSV_FILE = f"network_audit_{TIMESTAMP}.csv"

# Define command sets for different OS types
# Netmiko uses these commands with use_textfsm=True to parse the output
COMMAND_MAP = {
    'cisco_ios': {
        'version': 'show version',
        'interfaces': 'show ip interface brief',
        'cdp': 'show cdp neighbors detail',
    },
    'cisco_nxos': {
        'version': 'show version',
        'interfaces': 'show ip interface brief',
        'cdp': 'show cdp neighbors detail',
    },
    # ASA does not support CDP in the same way, so it's omitted here.
    'cisco_asa': {
        'version': 'show version',
        'interfaces': 'show interface ip brief',
    }
}

# --- Logging Setup ---
# Setup logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
# Suppress noisy netmiko logs unless they are warnings or worse
logging.getLogger("netmiko").setLevel(logging.WARNING)


# --- Main Worker Function (Executed by each thread) ---

def device_worker(work_queue, csv_writer, username, password, secret, pbar):
    """
    Worker function to be executed by each thread.
    Pulls a device from the queue, connects, runs commands, parses data, and writes to CSV.
    """
    while not work_queue.empty():
        ip = work_queue.get()
        thread_name = threading.current_thread().name
        log = logging.getLogger(f"{thread_name}-{ip}")
        log.info(f"Connecting to device {ip}...")

        base_device = {
            'device_type': 'autodetect',
            'host': ip,
            'username': username,
            'password': password,
            'secret': secret,
            'timeout': 30,  # Increased timeout for stability
        }

        try:
            with ConnectHandler(**base_device) as net_connect:
                detected_os = net_connect.device_type
                log.info(f"Successfully connected. Detected OS: {detected_os}")

                if detected_os not in COMMAND_MAP:
                    log.warning(f"Unsupported OS: {detected_os}. Skipping.")
                    csv_writer.writerow({'ip_address': ip, 'status': f'Unsupported OS: {detected_os}'})
                    continue

                commands = COMMAND_MAP[detected_os]

                # --- 1. Get structured data using TextFSM ---
                version_data = net_connect.send_command(commands['version'], use_textfsm=True)
                interface_data = net_connect.send_command(commands['interfaces'], use_textfsm=True)
                
                cdp_data = []
                if 'cdp' in commands:
                    cdp_data = net_connect.send_command(commands['cdp'], use_textfsm=True)

                # --- 2. Process and combine the data ---
                if not version_data:
                    log.error("Could not parse version data.")
                    csv_writer.writerow({'ip_address': ip, 'status': 'Failed to parse version'})
                    continue
                
                device_info = version_data[0] # TextFSM returns a list
                hostname = device_info.get('hostname', net_connect.find_prompt().replace("#", "").strip())
                
                # Create a lookup dictionary for CDP neighbors by local interface
                cdp_lookup = {
                    item['local_port']: {
                        'neighbor': item['destination_host'],
                        'neighbor_ip': item['management_ip'],
                        'neighbor_platform': item['platform'],
                        'neighbor_port': item['remote_port'],
                    } for item in cdp_data
                }

                # --- 3. Write data to CSV ---
                if not interface_data:
                    log.info("No interface data parsed. Writing device summary row.")
                    row = {
                        'hostname': hostname, 'ip_address': ip,
                        'model': device_info.get('hardware'), 'version': device_info.get('version'),
                        'status': 'OK'
                    }
                    csv_writer.writerow(row)
                else:
                    for iface in interface_data:
                        local_int = iface.get('intf')
                        cdp_neighbor_info = cdp_lookup.get(local_int, {})
                        
                        row = {
                            'hostname': hostname,
                            'ip_address': ip,
                            'model': device_info.get('hardware'),
                            'version': device_info.get('version'),
                            'interface': local_int,
                            'interface_ip': iface.get('ipaddr'),
                            'interface_status': iface.get('status'),
                            'protocol_status': iface.get('proto'),
                            'neighbor_device': cdp_neighbor_info.get('neighbor'),
                            'neighbor_platform': cdp_neighbor_info.get('neighbor_platform'),
                            'neighbor_interface': cdp_neighbor_info.get('neighbor_port'),
                            'status': 'OK',
                        }
                        csv_writer.writerow(row)

        except NetmikoAuthenticationException:
            log.error("Authentication failed.")
            csv_writer.writerow({'ip_address': ip, 'status': 'Authentication Failed'})
        except NetmikoTimeoutException:
            log.error("Connection timed out.")
            csv_writer.writerow({'ip_address': ip, 'status': 'Connection Timeout'})
        except Exception as e:
            log.critical(f"An unexpected error occurred: {e}", exc_info=True)
            csv_writer.writerow({'ip_address': ip, 'status': f'Error: {e}'})
        finally:
            work_queue.task_done()
            pbar.update(1)


# --- Thread-safe CSV Writer ---
class ThreadSafeDictWriter:
    def __init__(self, f, fieldnames):
        self.writer = csv.DictWriter(f, fieldnames=fieldnames, restval='N/A')
        self.lock = threading.Lock()
    def writeheader(self):
        with self.lock:
            self.writer.writeheader()
    def writerow(self, row):
        with self.lock:
            self.writer.writerow(row)

# --- Main Execution Block ---
def main():
    """
    Main function to orchestrate the threading, logging, and file I/O.
    """
    try:
        with open(DEVICE_FILE, 'r') as f:
            devices = [line.strip() for line in f if line.strip()]
        if not devices:
            logging.error(f"Device file '{DEVICE_FILE}' is empty.")
            return
    except FileNotFoundError:
        logging.error(f"Device file '{DEVICE_FILE}' not found.")
        return

    # Get credentials securely
    username = input("Enter SSH Username: ")
    password = getpass("Enter SSH Password: ")
    secret = getpass("Enter ENABLE secret (optional, press Enter to skip): ")

    # Setup work queue
    work_queue = queue.Queue()
    for ip in devices:
        work_queue.put(ip)

    # Setup CSV output file
    fieldnames = [
        'hostname', 'ip_address', 'model', 'version', 'status', 'interface',
        'interface_ip', 'interface_status', 'protocol_status', 'neighbor_device',
        'neighbor_platform', 'neighbor_interface'
    ]
    
    with open(CSV_FILE, 'w', newline='') as csvfile, tqdm(
        total=len(devices), desc="Auditing Devices", unit="device"
    ) as pbar:
        writer = ThreadSafeDictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Start threads
        threads = []
        for i in range(min(NUM_THREADS, len(devices))):
            thread = threading.Thread(
                target=device_worker,
                args=(work_queue, writer, username, password, secret, pbar),
                name=f"Worker-{i+1}"
            )
            thread.start()
            threads.append(thread)

        # Wait for queue to be empty
        work_queue.join()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    logging.info(f"\n--- Audit complete! ---")
    logging.info(f"Results saved to: {CSV_FILE}")
    logging.info(f"Execution log saved to: {LOG_FILE}")


if __name__ == '__main__':
    main()
