# System inspector (Flask + psutil)

## Description
A lightweight real-time system monitoring dashboard implemented with Flask that collects and displays CPU, memory, disk, and network metrics using `psutil`. Intended for local use to observe system performance and I/O behavior.

## Features
- Real-time CPU usage and per-core statistics
- CPU frequency information
- Memory usage and summary
- Disk I/O and usage metrics
- Network upload/download tracking
- Simple single-file Flask application for easy deployment

## Prerequisites
- Python 3.10 or newer is recommended
- Basic knowledge of creating and activating Python virtual environments
- `app.py` (the Flask application) must be present in the project root

## Installation

> Note: Use the instructions that correspond to your operating system.

### macOS / Linux
1. Open a terminal.
2. (Optional) Ensure Python 3 is installed:
   ```
   python3 --version
   ```
Create and activate a virtual environment:
```
python3 -m venv venv
source venv/bin/activate
```
Upgrade pip and install dependencies:

```
python -m pip install --upgrade pip
pip install -r requirements.txt
```
Run the application:

```
python app.py
```
Open a browser and navigate to:

```
http://127.0.0.1:5000
```

Check Python version:

```
python --version
```

powershell
```
python -m venv venv
.\venv\Scripts\Activate.ps1
```
If execution policy prevents activation, run PowerShell as Administrator and allow script execution (or use Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned), then reactivate.

Upgrade pip and install dependencies:

powershell
```
python -m pip install --upgrade pip
pip install -r requirements.txt
```
Run the application:

powershell
```
python app.py
```
Open a browser and navigate to:

cpp
```
http://127.0.0.1:5000
```
Running without a virtual environment
If you choose not to use a virtual environment, ensure the system Python's pip is used and you have privileges to install packages:

The app gathers system metrics using psutil. No additional configuration is required for local monitoring.

## Project structure


advanced-system-monitor/

├── app.py

├── requirements.txt

└── README.md

Requirements (summary)

Python 3.10+

See requirements.txt for package versions

Troubleshooting
ModuleNotFoundError: Ensure the virtual environment is activated and pip install -r requirements.txt completed without errors.

Permission errors on Windows activating venv: adjust PowerShell execution policy or run Command Prompt and use venv\Scripts\activate.bat.

Port already in use: update the port in app.run(host='127.0.0.1', port=5000) or stop the process using the port.

Security notes
This application is intended for local, development, or trusted-network use only. Do not expose the Flask dev server directly to the public internet without adding proper authentication and using a production WSGI server.

Contributing
Open an issue or submit a pull request with improvements (e.g., production-ready deployment, authentication, frontend enhancements).

Author
### Aditya Diwan
