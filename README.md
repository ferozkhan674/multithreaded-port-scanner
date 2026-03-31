🚀 Multi-threaded Port Scanner (Python)

A fast, lightweight, and beginner-friendly TCP port scanner built in Python. 

This tool can scan single hosts or entire networks (CIDR ranges) to identify open ports, 
associated services, and optionally perform banner grabbing for deeper insights.

-----------------------------------------------------------
✨ Features

⚡ Multi-threaded scanning for high performance

🌐 Supports IP addresses, hostnames, and CIDR ranges

🔎 Detects common services (HTTP, SSH, FTP, etc.)

🧾 Optional banner grabbing for service identification

🎯 Custom port ranges and flexible scan configurations

💾 Option to save scan results to a file

---------------------------------------------------------------

🛠️ Technologies Used

Python 3

socket — low-level network communication

threading & concurrent.futures — parallel execution

argparse — command-line interface

ipaddress — CIDR/network handling

----------------------------------------------------------------

📦 Installation
Clone the repository:

git clone https://github.com/ferozkhan674/multithreaded-port-scanner.git

cd multithreaded-port-scanner

No external dependencies required — uses only Python standard libraries.

--------------------------------------------------------------------

▶️ Usage

🔹 Basic scan (default ports 1–1024)

python3 scanner.py -t 127.0.0.1


🔹 Scan specific ports

python3 scanner.py -t 192.168.1.1 -p 22,80,443

🔹 Scan a network (CIDR)

python3 scanner.py -t 192.168.1.0/24

🔹 Enable banner grabbing

python3 scanner.py -t example.com --banner

🔹 Save results to a file

python3 scanner.py -t 127.0.0.1 -o results.txt

----------------------------------------------------------------------

⚙️ Command-line Options
Flag	Description

-t, --target	Target IP, hostname, or CIDR

-p, --ports	Port range (default: 1-1024)

--threads	Number of concurrent threads (default: 100)

--timeout	Connection timeout (seconds)

--banner	Enable banner grabbing

-o, --output	Save results to a file

--------------------------------------------------------------------------

📊 Sample Output

-------------------------------------------------------
  Host : 127.0.0.1
  Time : 0.45s  |  Open ports: 3
  
-------------------------------------------------------
  PORT     SERVICE         BANNER
  ----     -------         ------
  22        SSH            OpenSSH 7.6
  
  80        HTTP           Apache/2.4.41
  
  443       HTTPS
  
-------------------------------------------------------

⚠️ Disclaimer

This tool is intended for educational and ethical use only.
Only scan systems you own or have explicit permission to test
Unauthorized scanning may violate laws and regulations

-------------------------------------------------------

🧠 Inspiration

Inspired by professional tools like Nmap, this project is designed as a 
simplified and beginner-friendly implementation to help understand 
networking and cybersecurity concepts.

---------------------------------------------------------

📌 Future Improvements

🔄 UDP scanning support

🔍 Enhanced service/version detection

📄 JSON output format

📊 Progress bar & scan visualization

--------------------------------------------------------------

👤 Author

Feroz Khan, Cybersecurity Enthusiast

-------------------------------------------------------------
⭐ Support

If you found this project useful, consider giving it a star. It really helps!
