import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

def load_and_process_data(csv_path, target_ip=None):
    if not os.path.exists(csv_path):
        print(f"[ERROR] File not found: {csv_path}")
        return None

    df = pd.read_csv(csv_path)

    # Filter for specific target_ip if provided
    if target_ip:
        df = df[df["hostname"] == target_ip]

    # Remove invalid bandwidth entries
    df = df[df["bandwidth_mbps"] != "N/A"]
    if df.empty:
        print(f"[INFO] No usable data for {target_ip} in: {csv_path}")
        return None

    df["bandwidth_mbps"] = df["bandwidth_mbps"].astype(float)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    def get_time_of_day(hour):
        if 5 <= hour < 12:
            return "Morning"
        elif 12 <= hour < 16:
            return "Afternoon"
        elif 16 <= hour < 20:
            return "Evening"
        else:
            return "Night"

    df["time_of_day"] = df["timestamp"].dt.hour.apply(get_time_of_day)
    return df


def plot_hop_metrics(df, time_of_day, target_ip=None, out_dir="static",protocol="ICMP"):
    # Handle target_ip being None
    ip_safe = target_ip.replace(".", "_") if target_ip else "unknown"

    df_time = df[df["time_of_day"] == time_of_day]
    if df_time.empty:
        print(f"[INFO] No data for {time_of_day}, skipping...")
        return

    os.makedirs(out_dir, exist_ok=True)

    # RTT plot
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.lineplot(data=df_time, x="hop", y="rtt_ms", hue="usage_count", marker="o", ax=ax)
    ax.set_title(f"RTT per Hop - {time_of_day} for {target_ip if target_ip else 'Unknown IP'}")
    fig.savefig(f"{out_dir}/rtt_{time_of_day.lower()}_{ip_safe}_{protocol}.png")
    plt.close(fig)

    # Bandwidth plot
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.lineplot(data=df_time, x="hop", y="bandwidth_mbps", hue="usage_count", marker="o", ax=ax)
    ax.set_title(f"Bandwidth per Hop - {time_of_day} for {target_ip if target_ip else 'Unknown IP'}")
    fig.savefig(f"{out_dir}/bandwidth_{time_of_day.lower()}_{ip_safe}_{protocol}.png")
    plt.close(fig)



def generate_all_time_plots(protocol="ICMP", target_ip=None):
    if protocol.upper() == "ICMP":
        csv_path = "traceroute_icmp.csv"
    elif protocol.upper() == "UDP":
        csv_path = "traceroute_udp.csv"
    else:
        print("[ERROR] Unknown protocol. Use 'ICMP' or 'UDP'.")
        return

    df = load_and_process_data(csv_path, target_ip=target_ip)
    if df is None:
        print("[INFO] Skipping plot generation due to empty data.")
        return

    for t in ["Morning", "Afternoon", "Evening", "Night"]:
        plot_hop_metrics(df, t, target_ip, protocol= protocol.upper())


# Example usage
# generate_all_time_plots(protocol="UDP",target_ip = "ims.iitgn.ac.in")