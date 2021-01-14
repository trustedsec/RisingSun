// Author: @lo0pback (TrustedSec IR team)
// Thanks:
//  https://github.com/RedDrip7/SunBurst_DGA_Decode
//  https://blog.truesec.com/2020/12/17/the-solarwinds-orion-sunburst-supply-chain-attack/
//  https://www.netresec.com/?page=Blog&month=2020-12&post=Reassembling-Victim-Domain-Fragments-from-SUNBURST-DNS
//  https://securelist.com/sunburst-connecting-the-dots-in-the-dns-requests/99862/
//  https://www.fireeye.com/blog/threat-research/2020/12/sunburst-additional-technical-details.html

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
)

func decryptSecureString(secureString string) (decodedBytes []byte) {
    decodedBytes = base32Decode(secureString)
    hash64 := make([]byte,len(decodedBytes)-1)
    xorKey := decodedBytes[0]
    for i := 0; i < len(hash64); i++ {
        hash64[i] = byte(decodedBytes[i + 1] ^ xorKey);
    }

    return hash64;
}

func base32Decode(secureString string) (decodedBinary []byte) {
	base32Text := "ph2eifo3n5utg1j8d94qrvbmk0sal76c"
	newString := ""
	for _, char := range secureString {
		if strings.Contains(base32Text, string(char)) {
			newString += string(char)
		}
	}

	var buffer uint = 0
	var bitCount int = 0
	decodedBinary = make([]byte,0)

	for _, rune := range secureString {
		buffer |= uint(strings.Index(base32Text, string(rune)) << bitCount)
		bitCount += 5
		if bitCount > 7 {
			decodedBinary = append(decodedBinary, byte(buffer))
			buffer >>= 8
			bitCount -= 8
		}
	}

	return decodedBinary
}

func decode(str string) (decodedString string) {
	text := []byte("rq3gsalt6u1iyfzop572d49bnx8cvmkewhj")
	text2 := []byte("0_-.")
	decodedString = ""
	specialSymbol := false

	for i:=0; i<len(str); i++ {
		if specialSymbol {
			index := bytes.IndexByte(text, str[i]) - ((rand.Intn(8) % (len(text) / len(text2))) * len(text2))
			index = index % len(text2)
			if index < 0 {
				index += len(text2)
			}
			decodedString += string(text2[index % len(text2)])
			specialSymbol = false
			continue
		} 
		if bytes.IndexByte(text2, str[i]) >= 0 {
			specialSymbol = true
		} else {
			index := (bytes.IndexByte(text, str[i]) - 4) % len(text)
			if index < 0 {
				index += len(text)
			}

			decodedString += string(text[index])
		}
	}
	return string(decodedString)
}

func calculateUserId (macAddress string, adDomain string, machineGuid string) (hash64 []byte) {
	hash64 = []byte{0,0,0,0,0,0,0,0}
	// Calculate the UserId based on the data provided
	combinedString := macAddress + adDomain + machineGuid
	bytes := []byte(combinedString)
	array := md5.Sum(bytes)

	for i:=0; i<len(array); i++ {
		var num int = i % len(hash64)
		hash64[num] ^= array[i]
	}
	
	return hash64
}

func generateUserIds(hostInfoFile string) (hostIdMap map[string]string) {
	hf, err := os.Open(hostInfoFile)
    if err != nil {
        log.Fatal("[-] Error: ", err)
    }
    defer hf.Close()

    hostIdMap = make(map[string]string)

    // Iterate over the list of domains and process them
    scanner := bufio.NewScanner(hf)
    for scanner.Scan() {
    	hostInfo := scanner.Text()
    	macAddress := strings.Replace(strings.ToUpper(strings.Split(hostInfo,",")[0]),":","",-1) // "AFAFAFAFAFAF"
    	adDomain := strings.ToLower(strings.Split(hostInfo,",")[1]) // "sub.domain.corp"
    	machineGuid := strings.ToLower(strings.Split(hostInfo,",")[2]) // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    	hostName := strings.Split(hostInfo,",")[3]

    	hostUserId := fmt.Sprintf("%x", calculateUserId(macAddress, adDomain, machineGuid))

    	hostIdMap[hostUserId] = hostName 
    }
    return hostIdMap
}

func main() {
	// Check for sufficient args
	if len(os.Args) < 2 {
		log.Println("[-] Not enough arguments provided.")
		log.Println("\tUsage: RisingSun <host info file> <domains file>")
		log.Println("\tExample: RisingSun ./hosts.txt ./domains.txt")
		return
	}
	// Assign args to friendly variables
	hostInfoFile := os.Args[1]
	domainsFile := os.Args[2] // path to file containing domains
	

	// Verify that domainsFile is a valid file
	_, err := os.Stat(domainsFile) 
	if os.IsNotExist(err) {
		log.Fatal("[-] Error - File does not exist, or insufficient permissions: ", err)
	}

	df, err := os.Open(domainsFile)
    if err != nil {
        log.Fatal("[-] Error: ", err)
    }
    defer df.Close()

	// Verify that hostInfoFile is a valid file
	_, err = os.Stat(hostInfoFile) 
	if os.IsNotExist(err) {
		log.Fatal("[-] Error - Host info file does not exist, or insufficient permissions: ", err)
	}

	hostIdMap := generateUserIds(hostInfoFile)

    cf, err := os.Create("results.csv")
    if err != nil {
    	log.Fatal("[-] Error creating results.csv:", err)
    }
    defer cf.Close()

    csvWriter := csv.NewWriter(cf)
    defer csvWriter.Flush()

    columnHeader := []string{"C2 domain","Decoded AD domain","Decoded UserId","Matched hostname"}
    err = csvWriter.Write(columnHeader)
	if err != nil {
		log.Fatal("[-] Error writing to CSV file:", err)
	}

    var decodedDomain string

    // Iterate over the list of domains and process them
    scanner := bufio.NewScanner(df)
    for scanner.Scan() {
    	fqdn := scanner.Text()
    	subdomain := strings.Split(fqdn,".")[0]
    	if len(subdomain) < 16 {
    		continue
    	}
    	
    	// The first 16 bytes of the C2 domain contains the "secure string", which contains
    	// the UserId specific to the host. The remaining bytes represent the AD domain of the host.
    	secureString := subdomain[:16]
    	encodedDomain := subdomain[16:]

    	// Retrieve the UserId from the "secure string"
    	userIdBytes := decryptSecureString(secureString)[:8]
    	userIdString := fmt.Sprintf("%x",userIdBytes)

    	if strings.HasPrefix(string(encodedDomain), "00") {
    		decodedDomain = string(base32Decode(encodedDomain[2:]))
    	} else {
    		decodedDomain = decode(encodedDomain)
    	}

    	line := []string{strings.TrimSpace(fqdn), decodedDomain, userIdString}

    	for hostUserId, hostname := range hostIdMap {
    		if hostUserId == fmt.Sprintf("%x",userIdBytes) {
    			line = append(line, hostname)
				fmt.Printf("[+] Found a match! The hostname %s generated the domain %s\n",hostname, fqdn)
			}
    	}
    	
    	err := csvWriter.Write(line)
    	if err != nil {
    		log.Fatal("[-] Error writing to CSV file:", err)
    	}

    }
    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}
