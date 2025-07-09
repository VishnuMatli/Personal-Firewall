import cmd

class FirewallCLI(cmd.Cmd):
    prompt = 'firewall> '
    
    def __init__(self, firewall):
        super().__init__()
        self.firewall = firewall
    
    def do_add_rule(self, arg):
        """Add a new firewall rule: add_rule type value action [protocol] [port]"""
        args = arg.split()
        if len(args) < 3:
            print("Usage: add_rule type value action [protocol] [port]")
            return
        
        rule_type = args[0]
        value = args[1]
        action = args[2]
        protocol = args[3] if len(args) > 3 else None
        port = int(args[4]) if len(args) > 4 else None
        
        self.firewall.add_rule(rule_type, value, action, protocol, port)
    
    def do_start(self, arg):
        """Start the firewall: start [interface]"""
        interface = arg if arg else None
        print(f"Starting firewall on interface {interface if interface else 'default'}...")
        self.firewall.start(interface)
    
    def do_apply_iptables(self, arg):
        """Apply rules to system iptables"""
        self.firewall.apply_iptables_rules()
    
    def do_exit(self, arg):
        """Exit the firewall"""
        print("Exiting...")
        return True

if __name__ == "__main__":
    firewall = PersonalFirewall()
    
    # Add some default rules
    firewall.add_rule('ip', '192.168.1.100', 'block')
    firewall.add_rule('port', 22, 'allow', 'tcp')
    firewall.add_rule('port', 80, 'allow', 'tcp')
    firewall.add_rule('port', 443, 'allow', 'tcp')
    firewall.add_rule('port', 3389, 'block', 'tcp')  # Block RDP
    
    cli = FirewallCLI(firewall)
    cli.cmdloop()