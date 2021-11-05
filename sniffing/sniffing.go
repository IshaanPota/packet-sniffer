package sniffing

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	tcpLayer layers.TCP
)

func SniffPackets(name string, snaplen int32, promisc bool, timeout time.Duration) {

	handler, err := pcap.OpenLive(name, snaplen, promisc, timeout)
	if err != nil {
		fmt.Println(err)
	}
	defer handler.Close()

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())

	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}

func printPacketInfo(packet gopacket.Packet) {

	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()


	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Print(applicationLayer.LayerContents())

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
