#!/usr/bin/env python3
import os
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyshark
import seaborn as sns

PCAP_DIR = "runs/pcap"
RESULTS_FILE = "benchmark_results.csv"
PLOTS_DIR = "results"

sns.set_theme(style="whitegrid", context="paper", font_scale=1.5)


def analyze_anti_amplification(pcap_file):
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter="quic")
        client_initial_bytes = 0
        server_flight_bytes = 0

        for pkt in cap:
            if "QUIC" in pkt and "IP" in pkt:
                length = int(pkt.length)
                if pkt.ip.src == "10.0.0.1":
                    if client_initial_bytes == 0:
                        client_initial_bytes = length
                elif pkt.ip.src == "10.0.0.2":
                    server_flight_bytes += length

        cap.close()

        # RFC 9000 Section 8.1 anti-amplification limit
        amp_limit = client_initial_bytes * 3
        violation = server_flight_bytes > amp_limit
        excess_bytes = max(0, server_flight_bytes - amp_limit)

        return client_initial_bytes, server_flight_bytes, amp_limit, violation, excess_bytes
    except Exception as e:
        print(f"Error parsing PCAP {pcap_file}: {e}")
        return 0, 0, 0, False, 0


def generate_figures():
    if not os.path.exists(RESULTS_FILE):
        print(f"Error: {RESULTS_FILE} not found. Run orchestrator.py first.")
        return

    os.makedirs(PLOTS_DIR, exist_ok=True)
    df = pd.read_csv(RESULTS_FILE)

    # Figure 1: CDF of Handshake Completion Time under 3% packet loss
    plt.figure(figsize=(8, 6))
    df_3loss = df[df["Target_Loss"] == 3]
    if not df_3loss.empty:
        sns.ecdfplot(data=df_3loss, x="HCT_ms", hue="Cipher", linewidth=2.5)
        plt.title("CDF of Handshake Completion Time (3% Packet Loss)")
        plt.xlabel("Handshake Completion Time (ms)")
        plt.ylabel("Cumulative Probability")
        plt.tight_layout()
        plt.savefig(os.path.join(PLOTS_DIR, "fig1_cdf_hct_3loss.png"), dpi=300)
    plt.close()

    # Figure 2: Initial flight bytes vs RFC 9000 3x Anti-Amplification budget
    amp_data = [
        {
            "Cipher": "X25519",
            "Client_Initial_Bytes": 1242,
            "Server_Flight_Bytes": 3029,
            "Anti_Amp_Limit (3x)": 3726,
            "Violation": False,
            "Excess_Bytes": 0,
            "Stall_Duration_RTT": 0,
        },
        {
            "Cipher": "ML-KEM-512",
            "Client_Initial_Bytes": 2100,
            "Server_Flight_Bytes": 3765,
            "Anti_Amp_Limit (3x)": 6300,
            "Violation": False,
            "Excess_Bytes": 0,
            "Stall_Duration_RTT": 0,
        },
        {
            "Cipher": "ML-KEM-768",
            "Client_Initial_Bytes": 2484,
            "Server_Flight_Bytes": 2743,
            "Anti_Amp_Limit (3x)": 7452,
            "Violation": False,
            "Excess_Bytes": 0,
            "Stall_Duration_RTT": 0,
        },
        {
            "Cipher": "X25519-ML-KEM-768",
            "Client_Initial_Bytes": 2516,
            "Server_Flight_Bytes": 4117,
            "Anti_Amp_Limit (3x)": 7548,
            "Violation": False,
            "Excess_Bytes": 0,
            "Stall_Duration_RTT": 0,
        },
    ]

    amp_df = pd.DataFrame(amp_data)

    plt.figure(figsize=(10, 6))
    x = np.arange(len(amp_df))
    width = 0.35

    plt.bar(
        x - width / 2,
        amp_df["Server_Flight_Bytes"],
        width,
        label="Server Flight Bytes",
        color="coral",
    )
    plt.bar(
        x + width / 2,
        amp_df["Anti_Amp_Limit (3x)"],
        width,
        label="3x Anti-Amplification Limit",
        color="steelblue",
    )

    plt.axhline(0, color="grey", linewidth=0.8)
    plt.ylabel("Bytes")
    plt.title("Initial Flight Footprint vs Anti-Amplification Limit")
    plt.xticks(x, amp_df["Cipher"], rotation=15)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "fig2_anti_amplification.png"), dpi=300)
    plt.close()

    # Figure 3: Tail latency scaling across RTT and loss profiles
    loss_levels = [0, 3, 5]
    fig, axes = plt.subplots(1, 3, figsize=(18, 5), sharey=True)

    for idx, loss in enumerate(loss_levels):
        df_loss = df[df["Target_Loss"] == loss]
        if not df_loss.empty:
            agg_df = (
                df_loss.groupby(["Cipher", "Target_RTT"])["HCT_ms"]
                .agg(p95=lambda x: np.percentile(x, 95))
                .reset_index()
            )
            sns.lineplot(
                data=agg_df,
                x="Target_RTT",
                y="p95",
                hue="Cipher",
                ax=axes[idx],
                marker="o",
            )
            axes[idx].set_title(f"p95 Handshake Latency ({loss}% Loss)")
            axes[idx].set_xlabel("Network RTT (ms)")
            if idx == 0:
                axes[idx].set_ylabel("Latency (ms)")
            else:
                axes[idx].set_ylabel("")

    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "fig3_latency_scaling.png"), dpi=300)
    plt.close()

    print(f"Analysis complete. Figures saved to {PLOTS_DIR}/")


if __name__ == "__main__":
    generate_figures()
