# SquidSideOut - Internal Port Scanner for Squid Proxy

<p align="center">
  <img src="/img/squidsideout.webp" width="200">
</p>

**SquidSideOut** is a tool to assess ports bound to `localhost` on a host running a Squid HTTP proxy (or basically any other HTTP based proxy). Additionally, the tool can be used to get a first glimpse of the network behind the proxy by scanning remote hosts accessible through the HTTP proxy.

###  Features

- Apart from scanning `localhost`, **SquidSideOut** can also be utilized to scan remote hosts through the Squid proxy, helping to understand and map the internal network behind the proxy.
- Though designed with Squid in mind, **SquidSideOut** can work with any HTTP-based proxy.
- Specify ports directly or use the provided file (`ports.txt`) to list individual ports or ranges.
-  The repository includes a `ports.txt` file with the 1000 most common ports by Nmap.
- Set the timeout to control how long the tool waits before determining if a port is closed. Fiddeling with these settings can help to prevent false positives on slow connections,.
- Scan multiple ports or hosts simultaneously using concurrent workers for faster results.
- **Debug Mode for Detailed Logs**: Enable debug mode to log detailed scanning activities, including failed connection attempts and retries.

### Use Cases
- Assessing Internal Ports on Squid Proxy: The core purpose of SquidSideOut is to detect ports bound to localhost on hosts running Squid proxy, revealing internal services that may otherwise be difficult to assess.
- Remote Network Discovery: The tool can also be used for scanning remote hosts behind the Squid proxy to understand the network topology and services available through the proxy.
- Security Testing: For penetration testers and system administrators to audit internal services exposed on localhost via Squid.

### Running the Tool

#### Scanning Localhost through Squid Proxy (Main Use Case)

To scan ports bound to `localhost` on the Squid proxy host:

```sh
go run SquidSideOut.go -proxy-ip <squid-proxy-ip> -proxy-port <proxy-port>
```
#### Scanning Remote Hosts Behind Squid Proxy

To get an initial overview of the network behind the Squid proxy by scanning remote hosts:

```sh
go run SquidSideOut.go -proxy-ip <squid-proxy-ip> -proxy-port <proxy-port> -ip <target-ip/cidr>
```

#### Port Range and Input Options
You can specify a port range or use a CSV list of ports:

```sh
# Specify a range of ports
go run SquidSideOut.go -proxy-ip <squid-proxy-ip> -proxy-port <proxy-port> -ports 80-8080

# Or, specify ports as a CSV list
go run SquidSideOut.go -proxy-ip <squid-proxy-ip> -proxy-port <proxy-port> -ports 22,80,443

```

#### Example Output

```sh
┌──(kali😈kali)-[~/SquidSideOut]
└─$ go run SquidSideOut.go -proxy-ip <squid-proxy-ip> -proxy-port <proxy-port> -debug
Scanning IP: 127.0.0.1
Port 8080 open on 127.0.0.1!
Port 443 open on 127.0.0.1!

Open ports on 127.0.0.1 (sorted):
443
8080
```