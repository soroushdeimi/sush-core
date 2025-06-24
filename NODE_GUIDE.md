# SpectralFlow Node Guide

*How to run a server node and help the network*

## Should You Run a Node?

Running a SpectralFlow node helps people get around censorship. But there are things to consider:

### Legal Stuff (Important!)
- **Check your laws** - proxy services aren't legal everywhere
- **Exit nodes are risky** - you'll appear as the source of all traffic
- **Middle nodes are safer** - you're just relaying encrypted data
- **Get legal advice** if you're unsure

### What You Need

**Bare minimum:**
- 1 CPU core, 512MB RAM, 10GB storage
- Decent internet (10+ Mbps)
- Static IP or dynamic DNS
- Open firewall ports

**Better setup:**
- 2+ CPU cores, 2GB+ RAM, 50GB+ storage  
- Fast connection (100+ Mbps)
- Multiple IP addresses
- VPS/dedicated server

## Types of Nodes

### Bridge Node (Start Here)
- **What it does**: Entry point for clients
- **Risk**: Low
- **Bandwidth needed**: Medium
- **Legal risk**: Minimal

### Middle Node  
- **What it does**: Relays traffic through the network
- **Risk**: Low-Medium
- **Bandwidth needed**: High
- **Legal risk**: Low

### Exit Node (Advanced Only)
- **What it does**: Final hop to websites
- **Risk**: High
- **Bandwidth needed**: High  
- **Legal risk**: High - websites see your IP

## Getting Started

### Install the Basics

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install python3 python3-pip git

# CentOS/RHEL
sudo yum install python3 python3-pip git

# Windows Server
# Download Python 3.9+ from python.org
# Download Git from git-scm.com
```

### 2. Download and Install SpectralFlow

```bash
git clone https://github.com/yourusername/spectralflow.git
cd spectralflow
pip3 install -r requirements.txt
```

### 3. Generate Node Identity

```bash
python spectralflow_cli.py generate-keys --output config/node-keys.json
```

## Configuration

### Basic Server Config (`config/server.conf`)

```ini
[network]
# Bind to all interfaces (0.0.0.0) or specific IP
bind_address = 0.0.0.0
bind_port = 9090

# Node type: bridge, middle, exit
node_type = bridge

[security]
# Path to your node keys
key_file = config/node-keys.json

# Require client authentication
require_auth = false

# Rate limiting (connections per minute)
rate_limit = 100

[logging]
level = INFO
file = logs/spectralflow-server.log
```

### Bridge Node Setup

```ini
[network]
bind_address = 0.0.0.0
bind_port = 9090
node_type = bridge
advertise = true

[bridge]
# Allow discovery by clients
public = true
contact_info = your-email@example.com
```

### Exit Node Setup (Advanced)

```ini
[network]
node_type = exit
bind_port = 9090

[exit_policy]
# Allowed destination ports
allowed_ports = 80,443,993,995

# Blocked destinations (example)
blocked_domains = illegal-site.com,malware.example

# Geographic restrictions
allowed_countries = US,CA,EU

[abuse]
# Contact for abuse reports
contact_email = abuse@yourdomain.com
abuse_url = https://yourdomain.com/abuse
```

## Firewall Configuration

### Linux (iptables)
```bash
# Allow SpectralFlow port
sudo iptables -A INPUT -p tcp --dport 9090 -j ACCEPT

# For exit nodes, allow outbound traffic
sudo iptables -A OUTPUT -j ACCEPT
```

### Windows Firewall
```powershell
# Allow inbound on port 9090
New-NetFirewallRule -DisplayName "SpectralFlow" -Direction Inbound -Port 9090 -Protocol TCP -Action Allow
```

## Running the Server

### Development/Testing
```bash
python spectralflow_cli.py server --config config/server.conf
```

### Production (Linux systemd)

1. **Create service file** (`/etc/systemd/system/spectralflow.service`):
```ini
[Unit]
Description=SpectralFlow Server
After=network.target

[Service]
Type=simple
User=spectralflow
WorkingDirectory=/opt/spectralflow
ExecStart=/usr/bin/python3 spectralflow_cli.py server --config config/server.conf
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

2. **Enable and start**:
```bash
sudo systemctl enable spectralflow
sudo systemctl start spectralflow
sudo systemctl status spectralflow
```

### Production (Windows Service)

Use NSSM (Non-Sucking Service Manager):
```cmd
nssm install SpectralFlow
nssm set SpectralFlow Application C:\Python39\python.exe
nssm set SpectralFlow AppParameters "spectralflow_cli.py server --config config\server.conf"
nssm set SpectralFlow AppDirectory C:\SpectralFlow
nssm start SpectralFlow
```

## Monitoring and Maintenance

### Check Server Status
```bash
python spectralflow_cli.py status --config config/server.conf
```

### View Logs
```bash
tail -f logs/spectralflow-server.log
```

### Monitor Resources
```bash
# CPU and memory usage
htop

# Network connections
netstat -tulpn | grep 9090

# Disk space
df -h
```

### Update SpectralFlow
```bash
git pull origin main
pip3 install -r requirements.txt --upgrade
sudo systemctl restart spectralflow
```

## Security Best Practices

### Server Hardening
- **Use dedicated user account** for SpectralFlow
- **Keep system updated** with security patches  
- **Use strong passwords** and key-based SSH
- **Enable fail2ban** to prevent brute force attacks
- **Regular backups** of configuration and keys

### Monitoring
- **Set up log monitoring** for suspicious activity
- **Monitor bandwidth usage** to detect abuse
- **Watch for legal notifications** (especially exit nodes)
- **Keep contact information current**

### Network Security
- **Use separate network** if possible
- **Consider VPS/dedicated hosting** for exit nodes
- **Implement bandwidth limiting** to prevent abuse
- **Use multiple servers** for redundancy

## Troubleshooting

### Port Binding Issues
```bash
# Check what's using the port
sudo netstat -tulpn | grep 9090

# Kill process if needed
sudo kill -9 <PID>
```

### High CPU Usage
- Check number of concurrent connections
- Adjust rate limiting in config
- Consider upgrading hardware

### Legal Issues (Exit Nodes)
- Have clear abuse policy and contact info
- Respond promptly to legal requests
- Consider liability insurance
- Document your good faith efforts

## Economic Considerations

### Costs
- **VPS/Dedicated Server**: $5-100+/month depending on specs
- **Bandwidth**: Often unlimited, but check ToS
- **Legal**: Potential legal consultation costs
- **Time**: Maintenance and monitoring

### Benefits
- **Support digital freedom** and privacy rights
- **Help users** in censored regions
- **Technical learning** experience
- **Community contribution**

## Getting Support

- **GitHub Issues**: Technical problems
- **Node Operator Chat**: Real-time support
- **Documentation**: Check ARCHITECTURE.md
- **Legal Resources**: Digital rights organizations

## Contributing to the Network

### Network Health
- **Run reliable nodes** with good uptime
- **Proper geographic distribution** 
- **Maintain updated software**
- **Report bugs and issues**

### Code Contributions  
- **Submit improvements** via GitHub
- **Documentation updates**
- **Security research** and responsible disclosure

---

**Running a SpectralFlow node helps protect digital rights worldwide. Thank you for your contribution to internet freedom!**

*Questions? Join our node operator community or open an issue on GitHub.*
