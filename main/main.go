package main

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func main() {

	var devices []pcap.Interface

	devices, err := pcap.FindAllDevs()

	for _, device := range devices {
		fmt.Println(device.Flags)
	}

	if err != nil {

		fmt.Print(err)
	}

}
