package main

import (
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

type result struct {
	IP   string
	Name string
	Type string
}

var (
	verbose bool
	output  string
	format  string
	timeout int
)

func init() {
	flag.BoolVar(&verbose, "v", false, "Display errors")
	flag.BoolVar(&verbose, "verbose", false, "Display errors")
	flag.StringVar(&output, "o", "", "Output file (default: stdout)")
	flag.StringVar(&output, "output", "", "Output file (default: stdout)")
	flag.StringVar(&format, "f", "txt", "Output format: txt, csv (default: txt)")
	flag.StringVar(&format, "format", "txt", "Output format: txt, csv (default: txt)")
	flag.IntVar(&timeout, "timeout", 5, "-t or --timeout : Socket timeout in seconds (default: 5)")
	flag.IntVar(&timeout, "t", 5, "-t or --timeout : Socket timeout in seconds (default: 5)")
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	w := tabwriter.NewWriter(os.Stderr, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "\t-v, --verbose\t\tDisplay errors")
	fmt.Fprintln(w, "\t-o, --output\t\tOutput file (default: stdout)")
	fmt.Fprintln(w, "\t-f, --format\t\tOutput format: txt, csv (default: txt)")
	fmt.Fprintln(w, "\t-t, --timeout\t\tSocket timeout in seconds (default: 5)")
	w.Flush()
}

func main() {
	flag.Parse()

	if format != "txt" && format != "csv" {
		fmt.Fprintln(os.Stderr, "Error: Invalid output format. It must be either txt or csv.")
		os.Exit(1)
	}

	if flag.NArg() < 2 {
		printUsage()
		os.Exit(1)
	}

	IPRange := flag.Arg(0)
	ports := strings.Split(flag.Arg(1), ",")

	var IPs []string
	if strings.Contains(IPRange, "-") {
		IPs = generateIPRange(IPRange)
	} else {
		IPs = generateCIDRRange(IPRange)
	}

	results := make(chan result)
	var wg sync.WaitGroup

	for _, IP := range IPs {
		for _, port := range ports {
			wg.Add(1)
			go func(IP, port string) {
				defer wg.Done()
				processIPPort(IP, port, results)
			}(IP, port)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Handle output based on format and output file.
	var outputWriter *os.File
	var err error
	var csvWriter *csv.Writer
	if output != "" {
		outputWriter, err = os.Create(output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error: unable to open output file: ", err)
			os.Exit(1)
		}
		defer outputWriter.Close()
	} else {
		outputWriter = os.Stdout
	}

	if format == "csv" {
		csvWriter = csv.NewWriter(outputWriter)
		defer csvWriter.Flush()
	}
	seenNames := make(map[string]map[string]bool)
	for r := range results {

		if _, ok := seenNames[r.IP]; !ok {
			seenNames[r.IP] = make(map[string]bool)
		}
		if seenNames[r.IP][r.Name] {
			continue
		}
		seenNames[r.IP][r.Name] = true
		if format == "csv" {
			csvWriter.Write([]string{r.IP, r.Name, r.Type})
		} else {
			fmt.Fprintf(outputWriter, "%s:%s\n", r.IP, r.Name)
		}
	}
}

func processIPPort(IP, port string, results chan<- result) {
	addr := fmt.Sprintf("%s:%s", IP, port)

	conn, err := createConn(addr)
	if err != nil {
		logError("Error: connect", addr, err)
		return
	}
	defer conn.Close()

	tlsConn, err := createTLSConn(conn)
	if err != nil {
		logError("Error: handshake ", addr, err)
		return
	}
	defer tlsConn.Close()

	processCertificates(tlsConn, IP, results)
	processRDNS(IP, results)
}

func createConn(addr string) (net.Conn, error) {
	timeoutDuration := time.Duration(timeout) * time.Second
	return net.DialTimeout("tcp", addr, timeoutDuration)
}

func createTLSConn(conn net.Conn) (*tls.Conn, error) {
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	err := tlsConn.Handshake()
	return tlsConn, err
}

func processCertificates(tlsConn *tls.Conn, IP string, results chan<- result) {
	certs := tlsConn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		name := cert.Subject.CommonName
		results <- result{IP: IP, Name: name, Type: "SSL"}
		for _, altName := range cert.DNSNames {
			results <- result{IP: IP, Name: name, Type: "SSL"}
			name = altName
		}
	}
}

func processRDNS(IP string, results chan<- result) {
	rDNS, err := net.LookupAddr(IP)
	if err != nil {
		logError("Error: rDNS lookup ", IP, err)
	} else {
		for _, dns := range rDNS {
			results <- result{IP: IP, Name: dns, Type: "rDNS"}
		}
	}
}

func logError(msg string, addr string, err error) {
	if verbose {
		fmt.Fprintln(os.Stderr, msg, addr, ": ", err)
	}
}

func generateCIDRRange(cidrRange string) []string {
	_, ipnet, err := net.ParseCIDR(cidrRange)
	if err != nil {
		fmt.Printf("Failed to parse CIDR: %s\n", err)
		os.Exit(1)
	}

	var IPs []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		IPs = append(IPs, ip.String())
	}

	return IPs
}

func generateIPRange(IPRange string) []string {
	IPs := strings.Split(IPRange, "-")
	startIP := net.ParseIP(IPs[0])
	endIP := net.ParseIP(IPs[1])

	var IPList []string
	for IP := startIP; !IP.Equal(endIP); inc(IP) {
		IPList = append(IPList, IP.String())
	}

	// Add the end IP to the list.
	IPList = append(IPList, endIP.String())

	return IPList
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
