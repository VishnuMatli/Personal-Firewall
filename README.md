# 🔥 Personal Firewall using Python

A lightweight and customizable **personal firewall** built using Python. This tool allows real-time network packet filtering based on user-defined rules (IP, Port, Protocol), with support for both **Command Line Interface (CLI)** and **Graphical User Interface (GUI)**. It also optionally integrates with **iptables** on Linux systems for system-level enforcement.

---

## 📌 Features

- 🛡️ Real-time packet sniffing using [Scapy](https://scapy.net/)
- 📋 Rule-based filtering (Block/Allow by IP, Port, Protocol)
- 🧠 Intelligent rule processing via class-based architecture
- 📝 Real-time traffic logging (to file and GUI display)
- 🖥️ GUI interface built with Tkinter
- 🔗 Optional iptables integration for Linux
- 💻 CLI fallback for advanced users
- 🔌 Easily extendable and modular

---

## 📁 Project Structure

```

personal-firewall/
│
├── firewall\_gui.py           # GUI controller
├── firewall\_cli.py           # CLI interface
├── personal\_firewall.py      # Core filtering logic
├── rules.json                # Sample user-defined rules
├── firewall.log              # Generated log file
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation

````

---

## ⚙️ Requirements

- Python 3.x
- Linux-based OS (for iptables support)
- Packages:
  - `scapy`
  - `tkinter` (comes with Python)
  - (Optional) `python-iptables` for iptables integration

Install using:

```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk iptables -y
pip install -r requirements.txt
````

> ⚠️ On Kali Linux or Debian with restrictions, use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Getting Started

### 🖥️ GUI Mode

Launch the graphical interface:

```bash
sudo python3 firewall_gui.py
```

**Tabs:**

* `Rules`: Add/remove rules (IP, Port, Protocol)
* `Logs`: View real-time packet logs
* `Control`: Select interface, start firewall, apply iptables

---

### 🔧 CLI Mode

Launch the firewall in CLI:

```bash
sudo python3 firewall_cli.py
```

**Available Commands:**

```bash
add_rule ip 192.168.1.100 block
add_rule port 23 block
add_rule protocol ICMP allow
start eth0
apply_iptables
exit
```

---

## 📝 Rules Format (`rules.json`)

You can define your rules in a JSON file:

```json
{
  "block_ip": ["192.168.1.100", "10.0.0.23"],
  "block_ports": [22, 23],
  "allow_protocols": ["TCP", "UDP"]
}
```

> The script reads and processes this at runtime to enforce filtering.

---

## 📄 Logging

All packet decisions (allowed/blocked) are logged in `firewall.log`.

**Sample Log Entry:**

```
2025-07-09 10:22:34 - INFO - Blocked packet: 10.0.0.5 → 192.168.1.10 TCP 23
```

Logs are also displayed in the GUI for real-time monitoring.

---

## 🔐 iptables Integration (Optional)

To apply your firewall rules at the system level:

* GUI: Click **"Apply to iptables"**
* CLI: Run command:

```bash
apply_iptables
```

This uses `python-iptables` to add corresponding `iptables` rules dynamically.

---

## 📈 Planned Features

* ⏲️ Time-based rule scheduling (e.g., block at night)
* 🌐 GeoIP-based country blocking
* 📊 Graph-based traffic statistics in GUI
* 🚨 Alerts for suspicious behavior (DoS, spoofing)
* 🔁 Rule import/export system

---

## 📂 Sample Usage Workflow

1. Launch GUI or CLI
2. Define rules (e.g., block a specific IP or port)
3. Start the firewall (sniffing packets)
4. (Optional) Apply rules to iptables
5. Monitor log output in real time

---

## 🧪 Testing Tips

* Use `ping` or `netcat` to test traffic:

  ```bash
  ping 192.168.1.100
  nc -zv 192.168.1.10 23
  ```
* Observe log output or blocked behavior

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👨‍💻 Author

**Matli Vishnu Vardhan Naidu**
[GitHub Profile](https://github.com/VishnuMatli) • [Email](mailto:matlikinnu@gmail.com)

---

## 🔗 Useful Links

* [Scapy Documentation](https://scapy.readthedocs.io/)
* [iptables Tutorial](https://help.ubuntu.com/community/IptablesHowTo)
* [Tkinter Reference](https://docs.python.org/3/library/tkinter.html)

---

## ✅ Status

Project is fully functional. GUI and CLI support are stable. Looking for feature requests and collaborators.

---
