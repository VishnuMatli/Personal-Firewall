from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import logging
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

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
            'type': rule_type,
            'value': value,
            'action': action,
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
            
            if rule['protocol'] and protocol != rule['protocol']:
                match = False
            if rule['port'] and port != rule['port']:
                match = False
            
            if match:
                return rule['action']
        
        return 'allow'
    
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

class FirewallGUI:
    def __init__(self, root, firewall):
        self.root = root
        self.firewall = firewall
        self.root.title("Personal Firewall")
        self.setup_ui()
        
    def setup_ui(self):
        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Rules tab
        rules_frame = ttk.Frame(notebook)
        notebook.add(rules_frame, text="Rules")
        
        # Add rule controls
        ttk.Label(rules_frame, text="Rule Type:").grid(row=0, column=0, padx=5, pady=5)
        self.rule_type = ttk.Combobox(rules_frame, values=["ip", "port", "protocol"])
        self.rule_type.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(rules_frame, text="Value:").grid(row=1, column=0, padx=5, pady=5)
        self.rule_value = ttk.Entry(rules_frame)
        self.rule_value.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(rules_frame, text="Action:").grid(row=2, column=0, padx=5, pady=5)
        self.rule_action = ttk.Combobox(rules_frame, values=["allow", "block"])
        self.rule_action.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(rules_frame, text="Protocol:").grid(row=3, column=0, padx=5, pady=5)
        self.rule_protocol = ttk.Combobox(rules_frame, values=["", "tcp", "udp", "icmp"])
        self.rule_protocol.grid(row=3, column=1, padx=5, pady=5)
        
        ttk.Label(rules_frame, text="Port:").grid(row=4, column=0, padx=5, pady=5)
        self.rule_port = ttk.Entry(rules_frame)
        self.rule_port.grid(row=4, column=1, padx=5, pady=5)
        
        ttk.Button(rules_frame, text="Add Rule", command=self.add_rule).grid(row=5, column=0, columnspan=2, pady=10)
        
        # Rules list
        self.rules_tree = ttk.Treeview(rules_frame, columns=("type", "value", "action", "protocol", "port"))
        self.rules_tree.heading("#0", text="ID")
        self.rules_tree.heading("type", text="Type")
        self.rules_tree.heading("value", text="Value")
        self.rules_tree.heading("action", text="Action")
        self.rules_tree.heading("protocol", text="Protocol")
        self.rules_tree.heading("port", text="Port")
        self.rules_tree.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        
        # Log tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Log")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Control tab
        control_frame = ttk.Frame(notebook)
        notebook.add(control_frame, text="Control")
        
        ttk.Label(control_frame, text="Network Interface:").grid(row=0, column=0, padx=5, pady=5)
        self.interface = ttk.Entry(control_frame)
        self.interface.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(control_frame, text="Start Firewall", command=self.start_firewall).grid(row=1, column=0, pady=10)
        ttk.Button(control_frame, text="Apply to iptables", command=self.apply_iptables).grid(row=1, column=1, pady=10)
        
        # Configure grid weights
        rules_frame.grid_rowconfigure(6, weight=1)
        rules_frame.grid_columnconfigure(1, weight=1)
        
        # Redirect logs to GUI
        self.setup_log_redirect()
        self.update_rules_list()
    
    def add_rule(self):
        rule_type = self.rule_type.get()
        value = self.rule_value.get()
        action = self.rule_action.get()
        protocol = self.rule_protocol.get() if self.rule_protocol.get() else None
        try:
            port = int(self.rule_port.get()) if self.rule_port.get() else None
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        if not rule_type or not value or not action:
            messagebox.showerror("Error", "Type, value and action are required")
            return
        
        self.firewall.add_rule(rule_type, value, action, protocol, port)
        self.update_rules_list()
    
    def update_rules_list(self):
        self.rules_tree.delete(*self.rules_tree.get_children())
        for i, rule in enumerate(self.firewall.rules):
            self.rules_tree.insert("", "end", text=str(i+1), values=(
                rule['type'],
                rule['value'],
                rule['action'],
                rule['protocol'] if rule['protocol'] else "",
                rule['port'] if rule['port'] else ""
            ))
    
    def start_firewall(self):
        interface = self.interface.get() if self.interface.get() else None
        messagebox.showinfo("Info", f"Starting firewall on interface {interface if interface else 'default'}")
        # In a real app, you would run this in a separate thread
        # self.firewall.start(interface)
    
    def apply_iptables(self):
        self.firewall.apply_iptables_rules()
        messagebox.showinfo("Info", "iptables rules applied (if available)")
    
    def setup_log_redirect(self):
        class LogRedirect:
            def __init__(self, text_widget):
                self.text_widget = text_widget
            
            def write(self, message):
                self.text_widget.insert(tk.END, message)
                self.text_widget.see(tk.END)
            
            def flush(self):
                pass
        
        import sys
        sys.stdout = LogRedirect(self.log_text)
        sys.stderr = LogRedirect(self.log_text)

if __name__ == "__main__":
    firewall = PersonalFirewall()
    
    # Add some default rules for demonstration
    firewall.add_rule('ip', '192.168.1.100', 'block')
    firewall.add_rule('port', 22, 'allow', 'tcp')
    firewall.add_rule('port', 80, 'allow', 'tcp')
    firewall.add_rule('port', 443, 'allow', 'tcp')
    firewall.add_rule('port', 3389, 'block', 'tcp')
    
    root = tk.Tk()
    root.geometry("800x600")
    app = FirewallGUI(root, firewall)
    root.mainloop()