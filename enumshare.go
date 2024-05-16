package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

func main() {
	hostPtr := flag.String("H", "", "Remote host IP or hostname, or file containing a list of hosts")
	userPtr := flag.String("u", "", "Username for SMB authentication")
	passPtr := flag.String("p", "", "Password for SMB authentication")
	domainPtr := flag.String("d", "", "Domain for SMB authentication (optional)")

	flag.Parse()

	if *hostPtr == "" || *userPtr == "" || *passPtr == "" {
		fmt.Println("Usage: go run main.go -H <host_or_file> -u <username> -p <password> [-d <domain>]")
		return
	}

	hosts := []string{*hostPtr}
	if isFile(*hostPtr) {
		hosts = readLinesFromFile(*hostPtr)
	}

	for _, host := range hosts {
		fmt.Printf("Processing host: %s\n", host)
		processHost(host, *userPtr, *passPtr, *domainPtr)
	}
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func readLinesFromFile(filePath string) []string {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Failed to open file: %s\n", err)
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Failed to read file: %s\n", err)
	}

	return lines
}

func processHost(host, username, password, domain string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", host), 10*time.Second)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		log.Fatalf("failed to negotiate: %v", err)
	}
	defer s.Logoff()

	fmt.Printf("Connected to %s\n", host)

	shares, err := s.ListSharenames()
	if err != nil {
		log.Fatalf("failed to list shares: %v", err)
	}

	fmt.Printf("Enumerated shares:\n")
	fmt.Printf("%-25s | %-12s | %s\n", "Share", "Permission", "Remark")
	fmt.Println(strings.Repeat("-", 60))

	for _, share := range shares {
		readPerm := checkShareReadPermission(s, share)
		permission := "Read/Write"
		if !readPerm {
			permission = "None"
		}
		fmt.Printf("%-25s | %-12s | %s\n", share, permission, "N/A")
	}
	fmt.Println("\n" + strings.Repeat("=", 60) + "\n")
}

func checkShareReadPermission(session *smb2.Session, shareName string) bool {
	fs, err := session.Mount(shareName)
	if err != nil {
		return false
	}
	defer fs.Umount()

	_, err = fs.ReadDir("")
	if err != nil {
		return false
	}
	return true
}
