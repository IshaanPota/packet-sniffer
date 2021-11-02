package main

import (
	"fmt"
	"main/sniffing"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {

	var devices []pcap.Interface

	devices, err := pcap.FindAllDevs()

	for _, device := range devices {
		fmt.Println(device.Name)

	}

	name := devices[13].Name

	sniffing.SniffPackets(name, 1024, true, time.Hour)

	if err != nil {

		fmt.Print(err)
	}

}
