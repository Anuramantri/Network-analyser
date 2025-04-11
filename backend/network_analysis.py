# network_analysis.py
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

def load_and_process_data(csv_path="traceroute_output.csv"):
    df = pd.read_csv(csv_path)
    df = df[df["bandwidth_mbps"] != "N/A"]
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

def plot_hop_metrics(df, time_of_day, out_dir="static"):
    df_time = df[df["time_of_day"] == time_of_day]
    os.makedirs(out_dir, exist_ok=True)

    fig, ax = plt.subplots(figsize=(10, 6))
    sns.lineplot(data=df_time, x="hop", y="rtt_ms", hue="usage_count", marker="o", ax=ax)
    ax.set_title(f"RTT per Hop - {time_of_day}")
    fig.savefig(f"{out_dir}/rtt_{time_of_day.lower()}.png")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 6))
    sns.lineplot(data=df_time, x="hop", y="bandwidth_mbps", hue="usage_count", marker="o", ax=ax)
    ax.set_title(f"Bandwidth per Hop - {time_of_day}")
    fig.savefig(f"{out_dir}/bandwidth_{time_of_day.lower()}.png")
    plt.close(fig)

def generate_all_time_plots(csv_path="network_data.csv"):
    df = load_and_process_data(csv_path)
    for t in ["Morning", "Afternoon", "Evening", "Night"]:
        plot_hop_metrics(df, t)

if __name__ == "__main__":
    generate_all_time_plots("traceroute_output.csv")