# 🔍 Multi-threaded Port Scanner (Python)

A fast and beginner-friendly TCP port scanner built using Python. This tool scans single hosts or entire networks (CIDR) and identifies open ports along with their associated services.


## 🚀 Features

* ⚡ Multi-threaded scanning for high performance
* 🌐 Supports single IP, hostname, and CIDR ranges
* 🔎 Detects common services (HTTP, SSH, FTP, etc.)
* 🧾 Optional banner grabbing for service identification
* 🎯 Custom port ranges and scan configurations
* 💾 Save scan results to a file

## 🛠️ Technologies Used

* Python 3
* `socket` – network connections
* `threading` & `concurrent.futures` – parallel execution
* `argparse` – command-line interface
* `ipaddress` – CIDR/network handling

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/ferozkhan674/py-port-scanner.git
cd py-port-scanner
```

No external dependencies required.

## ▶️ Usage

Basic scan (default ports 1–1024):

```bash
python3 scanner.py -t 127.0.0.1
```

Scan specific ports:

```bash
python3 scanner.py -t 192.168.1.1 -p 22,80,443
```

Scan a network (CIDR):

```bash
python3 scanner.py -t 192.168.1.0/24
```

Enable banner grabbing:

```bash
python3 scanner.py -t example.com --banner
```

Save results to a file:

```bash
python3 scanner.py -t 127.0.0.1 -o results.txt
```

## ⚙️ Options

| Flag           | Description                      |
| -------------- | -------------------------------- |
| `-t, --target` | Target IP, hostname, or CIDR     |
| `-p, --ports`  | Port range (default: 1-1024)     |
| `--threads`    | Number of threads (default: 100) |
| `--timeout`    | Connection timeout               |
| `--banner`     | Enable banner grabbing           |
| `-o, --output` | Save output to file              |


## 📊 Sample Output

```
-------------------------------------------------------
  Host : 127.0.0.1
  Time : 0.45s  |  Open ports: 3
-------------------------------------------------------
  PORT     SERVICE         BANNER
  ----     -------         ------
  22       SSH             OpenSSH 7.6
  80       HTTP            Apache/2.4.41
  443      HTTPS
-------------------------------------------------------
```


## ⚠️ Disclaimer

This tool is intended for educational purposes only.

Only scan systems you own or have explicit permission to test. Unauthorized scanning may violate laws and regulations.

## 🧠 Inspiration

This project is inspired by industry tools like Nmap, but implemented in a simplified, beginner-friendly way for learning purposes.


## 📌 Future Improvements

* UDP scanning support
* Service/version detection enhancements
* JSON output format
* Progress bar visualization

## 👤 Author

Feroz Khan
Aspiring Cybersecurity Professional

## ⭐ Support

If you found this project useful, consider giving it a star ⭐
