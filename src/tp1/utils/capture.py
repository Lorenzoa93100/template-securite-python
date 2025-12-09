from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger
from collections import Counter
import time
import re

# Imports Scapy
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP


class Capture:
    def __init__(self):
        # Sélection de l'interface réseau
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []  # Stockage des paquets capturés
        self.protocols = Counter()  # Compteur pour chaque protocole
        self.capture_time = 0  # Durée de la capture
        self.suspicious_activities = []  # Liste des activités suspectes détectées

    def capture_trafic(self, duration=30):
        # Vérif que l'interface est bien définie
        if not self.interface:
            logger.error("No interface selected. Cannot capture traffic.")
            return
            
        try:
            logger.info(f"Starting packet capture on {self.interface} for {duration} seconds...")
            t_start = time.time()
            
            # Lancement de la capture avec Scapy
            self.packets = sniff(iface=self.interface, timeout=duration)
            
            t_end = time.time()
            self.capture_time = t_end - t_start
            
            nb_packets = len(self.packets)
            logger.info(f"Captured {nb_packets} packets in {self.capture_time:.2f} seconds")
            
            # Analyse initiale des protocoles
            self._count_protocols()
            
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
            
    def _count_protocols(self):
        # Remise à zéro du compteur
        self.protocols.clear()
        
        # Parcours de tous les paquets capturés
        for pkt in self.packets:
            # Détection des protocoles layer 2
            if ARP in pkt:
                self.protocols['ARP'] += 1
            
            # Détection des protocoles layer 3
            if IP in pkt:
                self.protocols['IP'] += 1
                
                # Détection des protocoles layer 4
                if TCP in pkt:
                    self.protocols['TCP'] += 1
                    
                    # Identification des applications TCP communes par port
                    tcp_layer = pkt[TCP]
                    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                        self.protocols['HTTP'] += 1
                    elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        self.protocols['HTTPS'] += 1
                    elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
                        self.protocols['SSH'] += 1
                    elif tcp_layer.dport == 21 or tcp_layer.sport == 21:
                        self.protocols['FTP'] += 1
                        
                elif UDP in pkt:
                    self.protocols['UDP'] += 1
                    
                    # Identification des applications UDP
                    udp_layer = pkt[UDP]
                    if udp_layer.dport == 53 or udp_layer.sport == 53:
                        self.protocols['DNS'] += 1
                    elif udp_layer.dport == 67 or udp_layer.dport == 68:
                        self.protocols['DHCP'] += 1
                        
                elif ICMP in pkt:
                    self.protocols['ICMP'] += 1
        
        logger.info(f"Protocol distribution: {dict(self.protocols)}")

    def sort_network_protocols(self):
        # Tri des protocoles par nombre de paquets (décroissant)
        return dict(self.protocols.most_common())
    def get_all_protocols(self):
        # Retourne tous les protocoles avec leur nombre de paquets
        return dict(self.protocols)
    def analyse(self, protocol_filter=None):
        # Vérification qu'on a bien des paquets à analyser
        if not self.packets:
            logger.warning("No packets captured. Cannot perform analysis.")
            return
            
        logger.info("Starting traffic analysis...")
        # RAZ de la liste des activités suspectes
        self.suspicious_activities = []
        
        # Récupération des infos sur les protocoles
        all_protocols = self.get_all_protocols()
        sorted_protocols = self.sort_network_protocols()
        
        # Filtrage par protocole si demandé
        filtered_packets = self.packets
        if protocol_filter:
            proto_upper = protocol_filter.upper()
            logger.info(f"Filtering packets for protocol: {proto_upper}")
            
            # Filtrage en fonction du protocole
            if proto_upper == 'TCP':
                filtered_packets = [p for p in self.packets if TCP in p]
            elif proto_upper == 'UDP':
                filtered_packets = [p for p in self.packets if UDP in p]
            elif proto_upper == 'ICMP':
                filtered_packets = [p for p in self.packets if ICMP in p]
            elif proto_upper == 'ARP':
                filtered_packets = [p for p in self.packets if ARP in p]
                
            logger.info(f"Found {len(filtered_packets)} packets matching filter {proto_upper}")
        
        # Lancement des différentes détections
        self._detect_arp_spoofing()
        self._detect_port_scanning()
        self._detect_sql_injection()
        self._detect_excessive_icmp()
        
        # Génération du résumé final
        self.summary = self.gen_summary()
        
    def _detect_arp_spoofing(self):
        # Dictionnaire pour tracker les associations IP-MAC
        ip_mac_map = {}
        
        # Récupération des paquets ARP
        arp_pkts = [p for p in self.packets if ARP in p]
        
        for pkt in arp_pkts:
            arp_layer = pkt[ARP]
            # Vérif si c'est une réponse ARP
            if arp_layer.op == 2:  # op=2 => ARP reply
                src_ip = arp_layer.psrc
                src_mac = arp_layer.hwsrc
                
                # Check si on a déjà vu cette IP avec un autre MAC
                if src_ip in ip_mac_map and ip_mac_map[src_ip] != src_mac:
                    logger.warning(f"Possible ARP spoofing detected: IP {src_ip} associated with multiple MACs: {ip_mac_map[src_ip]} and {src_mac}")
                    # Ajout à la liste des activités suspectes
                    self.suspicious_activities.append({
                        'type': 'ARP Spoofing',
                        'details': f"IP {src_ip} associated with multiple MACs",
                        'attacker_ip': src_ip,
                        'attacker_mac': src_mac,
                        'severity': 'High'
                    })
                else:
                    ip_mac_map[src_ip] = src_mac
    
    def _detect_port_scanning(self):
        # Suivi de l'activité des différentes IPs sources
        scan_activity = {}
        
        # Filtrage des paquets TCP
        tcp_pkts = [p for p in self.packets if TCP in p and IP in p]
        
        for pkt in tcp_pkts:
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                dst_port = pkt[TCP].dport
                
                # Init du compteur pour cette IP source
                if src_ip not in scan_activity:
                    scan_activity[src_ip] = {"targets": {}, "ports": set()}
                
                # Tracking des IPs cibles et ports
                if dst_ip not in scan_activity[src_ip]["targets"]:
                    scan_activity[src_ip]["targets"][dst_ip] = set()
                
                scan_activity[src_ip]["targets"][dst_ip].add(dst_port)
                scan_activity[src_ip]["ports"].add(dst_port)
        
        # Détection des scans de ports potentiels
        for src_ip, data in scan_activity.items():
            # Si une IP source s'est connectée à bcp de ports différents
            nb_ports = len(data["ports"])
            if nb_ports > 10:  # Seuil fixé à 10 ports
                logger.warning(f"Possible port scanning detected from {src_ip} - connected to {nb_ports} different ports")
                self.suspicious_activities.append({
                    'type': 'Port Scanning',
                    'details': f"Connected to {nb_ports} different ports",
                    'attacker_ip': src_ip,
                    'severity': 'Medium'
                })
    
    def _detect_sql_injection(self):
        # Patterns SQL injection les plus communs
        sql_patterns = [
            r"'\s*OR\s*'\s*'\s*=\s*'",  # ' OR ' = '
            r"--",                        # Commentaire SQL
            r"UNION\s+SELECT",            # UNION SELECT
            r"INSERT\s+INTO",             # INSERT INTO
            r"DROP\s+TABLE",              # DROP TABLE
            r"FROM\s+information_schema"  # Accès information_schema
        ]
        
        # Récupération des paquets HTTP (port 80)
        http_pkts = [p for p in self.packets if TCP in p and IP in p and 
                     (p[TCP].dport == 80 or p[TCP].sport == 80)]
        
        for pkt in http_pkts:
            if pkt.haslayer("Raw"):
                # Décodage du payload
                payload = pkt["Raw"].load.decode('utf-8', 'ignore').lower()
                
                # Recherche des patterns SQL dans le payload
                for pattern in sql_patterns:
                    if re.search(pattern.lower(), payload, re.IGNORECASE):
                        src_ip = pkt[IP].src
                        logger.warning(f"Possible SQL injection attempt from {src_ip}: {payload[:50]}...")
                        # Ajout de l'activité suspecte
                        self.suspicious_activities.append({
                            'type': 'SQL Injection',
                            'details': f"Suspicious pattern: {pattern}",
                            'attacker_ip': src_ip,
                            'severity': 'High'
                        })
                        break
    
    def _detect_excessive_icmp(self):
        # Comptage des paquets ICMP par source
        icmp_count = Counter()
        
        # Filtrage des paquets ICMP
        icmp_pkts = [p for p in self.packets if ICMP in p and IP in p]
        
        for pkt in icmp_pkts:
            src_ip = pkt[IP].src
            icmp_count[src_ip] += 1
        
        # Détection si une source envoie trop de paquets ICMP
        seuil = 20  # Seuil à ajuster selon les besoins
        for src_ip, nb_paquets in icmp_count.items():
            if nb_paquets > seuil:
                logger.warning(f"Excessive ICMP traffic from {src_ip}: {nb_paquets} packets")
                self.suspicious_activities.append({
                    'type': 'Potential DoS (ICMP flooding)',
                    'details': f"{nb_paquets} ICMP packets in {self.capture_time:.1f} seconds",
                    'attacker_ip': src_ip,
                    'severity': 'Medium'
                })

    def get_summary(self):
        # Retourne le résumé généré
        return self.summary

    def gen_summary(self):
        # Génération d'un résumé de la capture et de l'analyse
        summary = """
\n\n====== NETWORK TRAFFIC ANALYSIS SUMMARY ======\n\n"""
        
        # Statistiques de capture
        summary += f"Capture Duration: {self.capture_time:.2f} seconds\n"
        summary += f"Total Packets: {len(self.packets)}\n"
        summary += f"Interface: {self.interface}\n\n"
        
        # Distribution des protocoles
        summary += "===== PROTOCOL DISTRIBUTION =====\n"
        sorted_protos = self.sort_network_protocols()
        for proto, nb in sorted_protos.items():
            pct = (nb / len(self.packets)) * 100 if self.packets else 0
            summary += f"{proto}: {nb} packets ({pct:.1f}%)\n"
        
        # Analyse de sécurité
        summary += "\n===== SECURITY ANALYSIS =====\n"
        if self.suspicious_activities:
            nb_threats = len(self.suspicious_activities)
            summary += f"\n[!] ALERT: {nb_threats} suspicious activities detected!\n\n"
            
            # Liste de chaque activité suspecte
            for idx, act in enumerate(self.suspicious_activities, 1):
                summary += f"Suspicious Activity #{idx}:\n"
                summary += f"  Type: {act['type']}\n"
                summary += f"  Details: {act['details']}\n"
                summary += f"  Source IP: {act.get('attacker_ip', 'Unknown')}\n"
                if 'attacker_mac' in act:
                    summary += f"  Source MAC: {act['attacker_mac']}\n"
                summary += f"  Severity: {act['severity']}\n\n"
        else:
            summary += "\n[✓] No suspicious activities detected. Network traffic appears normal.\n"
        
        return summary
