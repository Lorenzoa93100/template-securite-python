from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger
from collections import Counter
import time

# Import Scapy components
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []  # Store captured packets
        self.protocols = Counter()  # Count protocol occurrences
        self.capture_time = 0  # Duration of capture
        self.suspicious_activities = []  # Store potential attacks

    def capture_trafic(self, duration: int = 30) -> None:
        """
        Capture network traffic from an interface for a specified duration
        Args:
            duration: Number of seconds to capture traffic (default: 30)
        """
        if not self.interface:
            logger.error("No interface selected. Cannot capture traffic.")
            return
            
        try:
            logger.info(f"Starting packet capture on {self.interface} for {duration} seconds...")
            start_time = time.time()
            
            # Start packet capture
            self.packets = sniff(iface=self.interface, timeout=duration)
            
            end_time = time.time()
            self.capture_time = end_time - start_time
            
            count = len(self.packets)
            logger.info(f"Captured {count} packets in {self.capture_time:.2f} seconds")
            
            # Initial protocol analysis
            self._count_protocols()
            
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            
    def _count_protocols(self) -> None:
        """
        Count the different protocols in captured packets
        """
        # Reset counter
        self.protocols.clear()
        
        for packet in self.packets:
            # Identify layer 2 protocols
            if ARP in packet:
                self.protocols['ARP'] += 1
            
            # Identify layer 3 protocols
            if IP in packet:
                # Count IP
                self.protocols['IP'] += 1
                
                # Identify layer 4 protocols
                if TCP in packet:
                    self.protocols['TCP'] += 1
                    
                    # Identify common TCP applications by port
                    tcp_packet = packet[TCP]
                    if tcp_packet.dport == 80 or tcp_packet.sport == 80:
                        self.protocols['HTTP'] += 1
                    elif tcp_packet.dport == 443 or tcp_packet.sport == 443:
                        self.protocols['HTTPS'] += 1
                    elif tcp_packet.dport == 22 or tcp_packet.sport == 22:
                        self.protocols['SSH'] += 1
                    elif tcp_packet.dport == 21 or tcp_packet.sport == 21:
                        self.protocols['FTP'] += 1
                        
                elif UDP in packet:
                    self.protocols['UDP'] += 1
                    
                    # Identify common UDP applications
                    udp_packet = packet[UDP]
                    if udp_packet.dport == 53 or udp_packet.sport == 53:
                        self.protocols['DNS'] += 1
                    elif udp_packet.dport == 67 or udp_packet.dport == 68:
                        self.protocols['DHCP'] += 1
                        
                elif ICMP in packet:
                    self.protocols['ICMP'] += 1
        
        logger.info(f"Protocol distribution: {dict(self.protocols)}")

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols
        Returns:
            dict: Dictionary of protocols sorted by count (most common first)
        """
        # Sort protocols by count (most common first)
        sorted_protocols = dict(self.protocols.most_common())
        return sorted_protocols
    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        Returns:
            dict: Dictionary with protocols as keys and packet counts as values
        """
        return dict(self.protocols)
    def analyse(self, protocol_filter: str = None) -> None:
        """
        Analyse all captured data and detect potential attacks
        
        This method checks for:
        - ARP spoofing attempts
        - Port scanning behavior
        - SQL injection attempts in HTTP traffic
        - Excessive ICMP (potential DoS)
        
        Args:
            protocol_filter: Optional filter to focus on specific protocol
        
        Updates:
            - suspicious_activities list with potential attacks
            - summary with analysis results
        """
        if not self.packets:
            logger.warning("No packets captured. Cannot perform analysis.")
            return
            
        logger.info("Starting traffic analysis...")
        self.suspicious_activities = []
        
        # Get protocol information
        all_protocols = self.get_all_protocols()
        sorted_protocols = self.sort_network_protocols()
        
        # Apply protocol filter if specified
        filtered_packets = self.packets
        if protocol_filter:
            protocol_filter = protocol_filter.upper()
            logger.info(f"Filtering packets for protocol: {protocol_filter}")
            
            if protocol_filter == 'TCP':
                filtered_packets = [p for p in self.packets if TCP in p]
            elif protocol_filter == 'UDP':
                filtered_packets = [p for p in self.packets if UDP in p]
            elif protocol_filter == 'ICMP':
                filtered_packets = [p for p in self.packets if ICMP in p]
            elif protocol_filter == 'ARP':
                filtered_packets = [p for p in self.packets if ARP in p]
                
            logger.info(f"Found {len(filtered_packets)} packets matching filter {protocol_filter}")
        
        # Detect ARP spoofing
        self._detect_arp_spoofing()
        
        # Detect port scanning
        self._detect_port_scanning()
        
        # Detect SQL injection in HTTP traffic
        self._detect_sql_injection()
        
        # Detect excessive ICMP (potential DoS)
        self._detect_excessive_icmp()
        
        # Generate summary
        self.summary = self.gen_summary()
        
    def _detect_arp_spoofing(self) -> None:
        """
        Detect potential ARP spoofing attacks
        """
        # Track IP-MAC mappings
        ip_mac_mapping = {}
        
        # Check for ARP packets
        arp_packets = [p for p in self.packets if ARP in p]
        
        for packet in arp_packets:
            arp = packet[ARP]
            # Check for ARP replies
            if arp.op == 2:  # ARP reply
                ip = arp.psrc
                mac = arp.hwsrc
                
                # Check if we've seen this IP with a different MAC
                if ip in ip_mac_mapping and ip_mac_mapping[ip] != mac:
                    logger.warning(f"Possible ARP spoofing detected: IP {ip} associated with multiple MACs: {ip_mac_mapping[ip]} and {mac}")
                    self.suspicious_activities.append({
                        'type': 'ARP Spoofing',
                        'details': f"IP {ip} associated with multiple MACs",
                        'attacker_ip': ip,
                        'attacker_mac': mac,
                        'severity': 'High'
                    })
                else:
                    ip_mac_mapping[ip] = mac
    
    def _detect_port_scanning(self) -> None:
        """
        Detect potential port scanning behavior
        """
        # Track source IPs and their target ports
        scanner_activity = {}
        
        # Filter TCP packets
        tcp_packets = [p for p in self.packets if TCP in p and IP in p]
        
        for packet in tcp_packets:
            if IP in packet and TCP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport
                
                # Initialize counter for this source IP
                if src_ip not in scanner_activity:
                    scanner_activity[src_ip] = {"targets": {}, "ports": set()}
                
                # Track target IPs and ports
                if dst_ip not in scanner_activity[src_ip]["targets"]:
                    scanner_activity[src_ip]["targets"][dst_ip] = set()
                
                scanner_activity[src_ip]["targets"][dst_ip].add(dst_port)
                scanner_activity[src_ip]["ports"].add(dst_port)
        
        # Check for potential port scanning
        for src_ip, data in scanner_activity.items():
            # Check if a source IP has connected to many ports
            if len(data["ports"]) > 10:  # Threshold for number of ports
                logger.warning(f"Possible port scanning detected from {src_ip} - connected to {len(data['ports'])} different ports")
                self.suspicious_activities.append({
                    'type': 'Port Scanning',
                    'details': f"Connected to {len(data['ports'])} different ports",
                    'attacker_ip': src_ip,
                    'severity': 'Medium'
                })
    
    def _detect_sql_injection(self) -> None:
        """
        Detect potential SQL injection attempts in HTTP traffic
        """
        # Common SQL injection patterns
        sql_injection_patterns = [
            r"'\s*OR\s*'\s*'\s*=\s*'", # ' OR ' = '
            r"--",                      # SQL comment
            r"UNION\s+SELECT",          # UNION SELECT
            r"INSERT\s+INTO",           # INSERT INTO
            r"DROP\s+TABLE",            # DROP TABLE
            r"FROM\s+information_schema" # information_schema access
        ]
        
        # Check HTTP packets (TCP port 80)
        http_packets = [p for p in self.packets if TCP in p and IP in p and 
                       (p[TCP].dport == 80 or p[TCP].sport == 80)]
        
        for packet in http_packets:
            if packet.haslayer("Raw"):
                payload = packet["Raw"].load.decode('utf-8', 'ignore').lower()
                
                # Check for SQL injection patterns
                for pattern in sql_injection_patterns:
                    import re
                    if re.search(pattern.lower(), payload, re.IGNORECASE):
                        src_ip = packet[IP].src
                        logger.warning(f"Possible SQL injection attempt from {src_ip}: {payload[:50]}...")
                        self.suspicious_activities.append({
                            'type': 'SQL Injection',
                            'details': f"Suspicious pattern: {pattern}",
                            'attacker_ip': src_ip,
                            'severity': 'High'
                        })
                        break
    
    def _detect_excessive_icmp(self) -> None:
        """
        Detect excessive ICMP traffic (potential DoS)
        """
        # Count ICMP packets by source
        icmp_sources = Counter()
        
        icmp_packets = [p for p in self.packets if ICMP in p and IP in p]
        
        for packet in icmp_packets:
            src_ip = packet[IP].src
            icmp_sources[src_ip] += 1
        
        # Check if any source has sent too many ICMP packets
        threshold = 20  # Adjust threshold as needed
        for src_ip, count in icmp_sources.items():
            if count > threshold:
                logger.warning(f"Excessive ICMP traffic from {src_ip}: {count} packets")
                self.suspicious_activities.append({
                    'type': 'Potential DoS (ICMP flooding)',
                    'details': f"{count} ICMP packets in {self.capture_time:.1f} seconds",
                    'attacker_ip': src_ip,
                    'severity': 'Medium'
                })

    def get_summary(self) -> str:
        """
        Return the generated summary
        Returns:
            str: Analysis summary
        """
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate a comprehensive summary of the capture and analysis
        Returns:
            str: Formatted summary text
        """
        summary = """
\n\n====== NETWORK TRAFFIC ANALYSIS SUMMARY ======\n\n"""
        
        # Add capture statistics
        summary += f"Capture Duration: {self.capture_time:.2f} seconds\n"
        summary += f"Total Packets: {len(self.packets)}\n"
        summary += f"Interface: {self.interface}\n\n"
        
        # Add protocol distribution
        summary += "===== PROTOCOL DISTRIBUTION =====\n"
        sorted_protocols = self.sort_network_protocols()
        for protocol, count in sorted_protocols.items():
            percentage = (count / len(self.packets)) * 100 if self.packets else 0
            summary += f"{protocol}: {count} packets ({percentage:.1f}%)\n"
        
        # Add security analysis
        summary += "\n===== SECURITY ANALYSIS =====\n"
        if self.suspicious_activities:
            summary += f"\n[!] ALERT: {len(self.suspicious_activities)} suspicious activities detected!\n\n"
            
            for i, activity in enumerate(self.suspicious_activities, 1):
                summary += f"Suspicious Activity #{i}:\n"
                summary += f"  Type: {activity['type']}\n"
                summary += f"  Details: {activity['details']}\n"
                summary += f"  Source IP: {activity.get('attacker_ip', 'Unknown')}\n"
                if 'attacker_mac' in activity:
                    summary += f"  Source MAC: {activity['attacker_mac']}\n"
                summary += f"  Severity: {activity['severity']}\n\n"
        else:
            summary += "\n[✓] No suspicious activities detected. Network traffic appears normal.\n"
        
        return summary
