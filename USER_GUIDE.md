# Sush Core User Guide

*How to set up and use Sush Core for private internet access*

## What's This Thing?

Sush Core is a proxy that helps you browse privately, especially if your internet is censored or monitored. Think of it as a smart tunnel that disguises your traffic and routes it through multiple servers.

## Getting It Running

### Install Python First
1. Grab Python 3.9+ from [python.org](https://python.org)
2. When installing, check "Add Python to PATH"

### Get Sush Core
```bash
git clone https://github.com/soroushdeimi/sush-core.git
cd sush-core
```

### Install the Stuff It Needs
```bash
pip install -r requirements.txt
```

## Basic Setup (Most People Want This)

### Client Setup

1. **Copy the example config:**
   ```bash
   copy config\client.conf.example config\client.conf
   ```

2. **Edit the config file:**
   - Open `config\client.conf` in any text editor
   - Find `server_host` and put in a real server address
   - Save it

3. **Start the proxy:**
   ```bash
   python sush_cli.py proxy 8080 <server_host> 9090
   ```

4. **Set up your browser:**
   - Go to browser settings → Network/Proxy
   - Set SOCKS5 proxy to `127.0.0.1:8080`
   - Done

Your traffic now goes through Sush Core.

## Browser Configuration

### Chrome/Edge
1. Settings → Advanced → System → Open proxy settings
2. Manual proxy setup
3. SOCKS proxy: `127.0.0.1:8080`

### Firefox
1. Settings → Network Settings → Settings
2. Manual proxy configuration
3. SOCKS Host: `127.0.0.1`, Port: `8080`
4. Select "SOCKS v5"

## Configuration Options

### Basic Settings (`config\client.conf`)

```ini
[network]
# Server to connect to
server_host = your-server.example.com
server_port = 9090

# Local proxy port
listen_port = 8080

[security]
# Threat level: low, medium, high, critical
threat_level = medium

# Enable ML detection
enable_ml = true
```

### Environment Variables (Alternative)

Set these instead of using config files:

```cmd
set SUSH_SERVER_HOST=your-server.example.com
set SUSH_SERVER_PORT=9090
set SUSH_THREAT_LEVEL=high
```

## Troubleshooting

### "No module named 'kyber_py'"
```bash
pip install kyber-py
```

### "Connection refused" 
- Check server address in config
- Try a different server
- Check your internet connection

### Browser can't connect
- Make sure Sush Core client is running
- Check proxy settings in browser
- Try restarting the client

### Slow connection
- Try `threat_level = low` for better performance
- Use a server closer to your location

## Security Tips

1. **Use different servers** - Don't always connect to the same server
2. **Enable ML detection** - Helps adapt to blocking attempts  
3. **Use HTTPS websites** - Adds extra encryption layer
4. **Restart periodically** - Refresh your connection

## Advanced Usage

### Command Line Options

```bash
# Start with custom config
python sush_cli.py interactive --log-level INFO

# Start with high security
python sush_cli.py interactive --log-level DEBUG

# Start on different port (proxy mode)
python sush_cli.py proxy 9050 <server_host> 9090
```

### Multiple Configurations

You can have different configs for different situations:

- `config\home.conf` - For home use
- `config\work.conf` - For workplace  
- `config\travel.conf` - For traveling

Switch between them:
```bash
python sush_cli.py proxy 8080 <server_host> 9090
```

## Getting Help

- **GitHub Issues**: Report bugs and problems
- **Discussions**: Ask questions and get help
- **Documentation**: Check `ARCHITECTURE.md` for technical details

## Safety and Legal Notice

- Sush Core is for legitimate privacy protection
- Respect local laws and regulations
- Don't use for illegal activities
- Use responsibly and ethically

---

*Need help? Open an issue on GitHub or check our discussion forum.*
