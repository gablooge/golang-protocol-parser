package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func printGoose() {
	fmt.Println("======= Welcome Goose =======")

	gooseFileHandle, err := pcap.OpenOffline("pcaps/goose.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer gooseFileHandle.Close()

	packetSource := gopacket.NewPacketSource(gooseFileHandle, LayerTypeGoose)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(LayerTypeGoose)
		if layersdata != nil {
			gooseLayerData, _ := layersdata.(*Goose)
			gooseData := gooseLayerData.Info
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			fmt.Println("goose.appId : ", gooseData.AppId)
			fmt.Println("goose.length : ", gooseData.Length)
			fmt.Println("goose.gocbRef : ", gooseData.GocbRef)
			fmt.Println("goose.timeallowedtolive : ", gooseData.Timeallowedtolive)
		}

	}
}

func printBLE() {
	fmt.Println("======= Welcome BLE =======")

	bleFileHandle, err := pcap.OpenOffline("pcaps/ble.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer bleFileHandle.Close()

	packetSource := gopacket.NewPacketSource(bleFileHandle, LayerTypeBLE)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(LayerTypeBLE)
		if layersdata != nil {
			bleLayerData, _ := layersdata.(*BLE)
			// bleData := bleLayerData.Info
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			fmt.Println("HCIPacketType : ", bleLayerData.HCIPacketType)
		}

	}
}

func main() {
	// printGoose()
	printBLE()

	// TODO: modbus
	// TODO: mqtt
	// TODO: lorawan

	fmt.Println("======= Done =======")
}
