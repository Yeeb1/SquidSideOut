package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"io/ioutil"
)

var debug bool

func main() {
	targetIP := flag.String("ip", "127.0.0.1", "Target IP or IP range (CIDR notation). Example: 192.168.1.1 or 192.168.1.0/24")
	portRange := flag.String("ports", "", "Port or port range to scan. Example: 80,443 or 20-100 (optional, defaults to ports.txt)")
	proxyIP := flag.String("proxy-ip", "192.168.1.1", "Squid proxy IP address")
	proxyPort := flag.String("proxy-port", "3128", "Squid proxy port")
	numWorkers := flag.Int("workers", 100, "Number of concurrent workers")
	timeoutThreshold := flag.Int("timeout", 5, "Timeout threshold in seconds to determine if a port is closed")
	debugFlag := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	debug = *debugFlag

	proxyURL := fmt.Sprintf("http://%s:%s", *proxyIP, *proxyPort)
	parsedProxyURL, err := url.Parse(proxyURL)
	if err != nil {
		fmt.Printf("Failed to parse proxy URL: %v\n", err)
		return
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedProxyURL),
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(*timeoutThreshold) * time.Second,
			KeepAlive: time.Duration(*timeoutThreshold) * time.Second,
		}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(*timeoutThreshold) * time.Second,
	}

	var ports []int
	if *portRange == "" {
		ports, err = readPortsFromFile("ports.txt")
		if err != nil {
			fmt.Printf("Failed to read ports from file: %v\n", err)
			return
		}
	} else {
		ports, err = parsePorts(*portRange)
		if err != nil {
			fmt.Printf("Invalid port range: %v\n", err)
			return
		}
	}

	ipList, err := parseIPRange(*targetIP)
	if err != nil {
		fmt.Printf("Invalid IP or CIDR range: %v\n", err)
		return
	}

	if debug {
		fmt.Printf("Debug: IPs to scan: %v\n", ipList)
		fmt.Printf("Debug: Ports to scan: %v\n", ports)
	}

	openPorts := scanIPsConcurrently(client, ipList, ports, *numWorkers)

	for ip, ports := range openPorts {
		if len(ports) > 0 {
			sort.Ints(ports)
			fmt.Printf("\nOpen ports on %s (sorted):\n", ip)
			for _, port := range ports {
				fmt.Println(port)
			}
		}
	}
}

func readPortsFromFile(filename string) ([]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "-") {
			rangeParts := strings.Split(line, "-")
			startPort, _ := strconv.Atoi(rangeParts[0])
			endPort, _ := strconv.Atoi(rangeParts[1])
			for port := startPort; port <= endPort; port++ {
				ports = append(ports, port)
			}
		} else {
			port, _ := strconv.Atoi(line)
			ports = append(ports, port)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ports, nil
}

func parsePorts(portString string) ([]int, error) {
	var ports []int
	if strings.Contains(portString, ",") {
		csvParts := strings.Split(portString, ",")
		for _, part := range csvParts {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port in CSV: %s", part)
			}
			ports = append(ports, port)
		}
	} else if strings.Contains(portString, "-") {
		rangeParts := strings.Split(portString, "-")
		startPort, err := strconv.Atoi(rangeParts[0])
		if err != nil {
			return nil, err
		}
		endPort, err := strconv.Atoi(rangeParts[1])
		if err != nil {
			return nil, err
		}
		for port := startPort; port <= endPort; port++ {
			ports = append(ports, port)
		}
	} else {
		port, err := strconv.Atoi(portString)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func parseIPRange(ipRange string) ([]string, error) {
	if strings.Contains(ipRange, "/") {
		ip, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, err
		}

		var ipList []string
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			ipList = append(ipList, ip.String())
		}

		if len(ipList) > 2 && ip.To4() != nil {
			ipList = ipList[1 : len(ipList)-1]
		}
		return ipList, nil
	}

	if net.ParseIP(ipRange) != nil {
		return []string{ipRange}, nil
	}

	return nil, fmt.Errorf("invalid IP or CIDR range")
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanIPsConcurrently(client *http.Client, ips []string, ports []int, numWorkers int) map[string][]int {
	openPortsMap := make(map[string][]int)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			ipOpenPorts := scanPorts(client, ip, ports, numWorkers)

			mu.Lock()
			openPortsMap[ip] = ipOpenPorts
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return openPortsMap
}

func scanPorts(client *http.Client, targetIP string, ports []int, numWorkers int) []int {
	openPorts := make([]int, 0)
	sem := make(chan struct{}, numWorkers)
	var wg sync.WaitGroup
	mu := &sync.Mutex{}

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", targetIP, p)

			if debug {
				fmt.Printf("Debug: Scanning port %d on IP %s\n", p, targetIP)
			}

			r, err := client.Get(fmt.Sprintf("http://%s", address))
			if err != nil {
				if debug {
					fmt.Printf("Debug: Failed to scan port %d on IP %s, error: %v\n", p, targetIP, err)
				}
				return
			}
			defer r.Body.Close()

			data, _ := ioutil.ReadAll(r.Body)
			if strings.Contains(string(data), "The requested URL could not be retrieved") {
				if debug {
					fmt.Printf("Debug: Port %d on IP %s returned 'The requested URL could not be retrieved'\n", p, targetIP)
				}
				return
			}

			mu.Lock()
			fmt.Printf("Port %d open on %s!\n", p, targetIP)
			openPorts = append(openPorts, p)
			mu.Unlock()

		}(port)
	}
	wg.Wait()
	return openPorts
}
