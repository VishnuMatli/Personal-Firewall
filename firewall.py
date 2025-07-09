from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import logging
import time

class PersonalFirewall:
    def __init__(self):
        self.rules = []
        self.log_file = "firewall.log"
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        logging.getLogger('').addHandler(console)
    
    def add_rule(self, rule_type, value, action, protocol=None, port=None):
        """Add a new firewall rule"""
        rule = {
            'type': rule_type,  # 'ip', 'port', 'protocol'
            'value': value,     # IP address, port number, or protocol name
            'action': action,   # 'allow' or 'block'
            'protocol': protocol,
            'port': port
        }
        self.rules.append(rule)
        logging.info(f"Added rule: {rule}")
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = None
            port = None
            
            if TCP in packet:
                protocol = 'tcp'
                port = packet[TCP].dport
            elif UDP in packet:
                protocol = 'udp'
                port = packet[UDP].dport
            
            # Check rules for this packet
            decision = self.check_rules(ip_src, ip_dst, protocol, port)
            
            if decision == 'block':
                logging.warning(f"Blocked packet: {ip_src} -> {ip_dst} {protocol} {port}")
                return
            else:
                logging.info(f"Allowed packet: {ip_src} -> {ip_dst} {protocol} {port}")
    
    def check_rules(self, ip_src, ip_dst, protocol, port):
        """Check packet against all rules"""
        for rule in self.rules:
            match = False
            
            if rule['type'] == 'ip':
                if ip_src == rule['value'] or ip_dst == rule['value']:
                    match = True
            elif rule['type'] == 'port' and port is not None:
                if port == rule['value']:
                    match = True
            elif rule['type'] == 'protocol' and protocol is not None:
                if protocol == rule['value']:
                    match = True
            
            # Additional protocol/port conditions
            if rule['protocol'] and protocol != rule['protocol']:
                match = False
            if rule['port'] and port != rule['port']:
                match = False
            
            if match:
                return rule['action']
        
        return 'allow'  # Default action if no rules match
    
    def start(self, interface=None):
        """Start the firewall"""
        logging.info("Starting personal firewall...")
        if interface:
            sniff(iface=interface, prn=self.packet_handler, store=0)
        else:
            sniff(prn=self.packet_handler, store=0)
    
    def apply_iptables_rules(self):
        """Apply rules to system iptables (Linux only)"""
        try:
            import iptc
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, "INPUT")
            
            # Flush existing rules (optional)
            # chain.flush()
            
            for rule in self.rules:
                if rule['action'] == 'block':
                    iptc_rule = iptc.Rule()
                    
                    if rule['type'] == 'ip':
                        iptc_rule.src = rule['value'] if rule['value'] == ip_src else ""
                        iptc_rule.dst = rule['value'] if rule['value'] == ip_dst else ""
                    
                    if rule['protocol']:
                        iptc_rule.protocol = rule['protocol']
                        if rule['port']:
                            match = iptc_rule.create_match(rule['protocol'])
                            match.dport = str(rule['port'])
                    
                    iptc_rule.target = iptc.Target(iptc_rule, "DROP")
                    chain.insert_rule(iptc_rule)
            
            logging.info("iptables rules applied successfully")
        except ImportError:
            logging.warning("iptables module not available (Linux only)")
        except Exception as e:
            logging.error(f"Error applying iptables rules: {str(e)}")