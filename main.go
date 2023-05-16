package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile string = "pcaps/goose.pcap"
	handle   *pcap.Handle
	err      error
)

func main() {
	// Open file instead of device
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, GooseLayerType)
	var i int
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(GooseLayerType)
		if layersdata != nil {
			gooseLayerData, _ := layersdata.(*GooseLayerPacket)
			gooseData := gooseLayerData.Data
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			fmt.Println("EtherType : ", hex.EncodeToString(gooseLayerData.EthernetType))
			fmt.Println("goose.appId : ", gooseData.AppId)
			fmt.Println("goose.length : ", gooseData.Length)
			fmt.Println("goose.gocbRef : ", gooseData.GocbRef)
			fmt.Println("goose.timeallowedtolive : ", gooseData.Timeallowedtolive)
		}

	}

	// TODO: modbus
	// TODO: mqtt
	// TODO: lorawan
}
