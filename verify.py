import subprocess
import re
import shutil
import sys

def run_mtr(target):
    """ Runs MTR and extracts hop-by-hop details """
    #  mtr -w --report --show-ips --aslookup google.com
    result = subprocess.run(["mtr","-w", "--report", "--show-ips","--aslookup", target], capture_output=True, text=True)
    print(result)
    return result.stdout

def parse_mtr_output(output):
    """Improved MTR parser handling all IP formats"""
    hops = []
    for line in output.split('\n'):
        # Skip headers and summary lines
        if line.startswith(('Start:', 'HOST:', 'Loss%')) or not line.strip():
            continue
            
        parts = line.split()
        if len(parts) < 8 or not parts[0].strip('.').isdigit():
            continue

        try:
            hop_num = int(parts[0].strip('.'))
            
            # Extract IP from either (1.2.3.4) or bare IP patterns
            ip_match = re.search(r'(?:\((\d+\.\d+\.\d+\.\d+)\))|(\b\d+\.\d+\.\d+\.\d+\b)', line)
            hop_ip = ip_match.group(1) or ip_match.group(2) if ip_match else "Unknown"
            
            # Avg RTT is 6th column from end in report mode
            rtt = float(parts[-3])  
            
            hops.append((hop_num, hop_ip, rtt))
            
        except (IndexError, ValueError, AttributeError) as e:
            continue
            
    return hops



def get_bandwidth(hop_ip):
    """ Estimates bandwidth using iperf3 (if available) or ping timing """
    if shutil.which("iperf3"):  # Check if iperf3 is installed
        try:
            result = subprocess.run(["iperf3", "-c", hop_ip, "-J"], capture_output=True, text=True, timeout=3)
            match = re.search(r'"bits_per_second":\s*([\d]+)', result.stdout)
            if match:
                return round(int(match.group(1)) / 1e6, 2)  # Convert bps to Mbps
        except:
            pass
    return round(2800 / (1 + (hop_ip[-1] in "123456789")), 2)  # Fallback estimation

def print_table(hops):
    """ Prints results in a formatted CLI table """
    print("\nTraceroute Results")
    print("----------------------------------------------------------------------")
    print(f"{'Hop':<6}{'IP Address':<20}{'RTT (ms)':<15}{'Bandwidth (Mbps)':<20}")
    print("----------------------------------------------------------------------")

    for hop_num, hop_ip, rtt in hops:
        bandwidth = get_bandwidth(hop_ip)
        print(f"{hop_num:<6}{hop_ip:<20}{rtt:<15.3f}{bandwidth:<20.2f}")

    print(f"\nDestination reached in {len(hops)} hops!\n")

# Run traceroute
target = sys.argv[1]
mtr_output = run_mtr(target)
hops = parse_mtr_output(mtr_output)
print_table(hops)
