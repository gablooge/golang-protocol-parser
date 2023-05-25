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

	packetSource := gopacket.NewPacketSource(gooseFileHandle, LayerTypeGOOSE)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(LayerTypeGoose)
		if layersdata != nil {
			gooseLayerData, _ := layersdata.(*GOOSE)
			gooseData := gooseLayerData.Info
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			fmt.Println("goose.appId : ", gooseData.AppID)
			fmt.Println("goose.length : ", gooseData.Length)
			fmt.Println("goose.gocbRef : ", gooseData.GocbRef)
			fmt.Println("goose.timeallowedtolive : ", gooseData.Timeallowedtolive)
			fmt.Println("goose.datset : ", gooseData.DatSet)
			fmt.Println("goose.t : ", gooseData.T)
			fmt.Println("goose.stnum : ", gooseData.StNum)
			fmt.Println("goose.sqnum : ", gooseData.SqNum)
			fmt.Println("goose.simulation : ", gooseData.Simulation)
			fmt.Println("goose.confrev : ", gooseData.ConfRev)
			fmt.Println("goose.ndscom : ", gooseData.NdsCom)
			fmt.Println("goose.numdatsetentries : ", gooseData.NumDatSetEntries)
		}
	}
}

func printBLE() {
	fmt.Println("======= Welcome BLE =======")

	bleFileHandle, err := pcap.OpenOffline("pcaps/blev2.pcap")
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

func printZigbee() {
	fmt.Println("======= Welcome Zigbee =======")
	zigbeeFileHandle, err := pcap.OpenOffline("pcaps/zigbee.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer zigbeeFileHandle.Close()

	packetSource := gopacket.NewPacketSource(zigbeeFileHandle, LayerTypeZigbee)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(LayerTypeZigbee)
		if layersdata != nil {
			zigbeeLayerData, _ := layersdata.(*Zigbee)
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			fmt.Println("zigbee.etherType : ", zigbeeLayerData.EthernetType)
			fmt.Println("zigbee.headerData : ", zigbeeLayerData.HeaderData)
			fmt.Println("zigbee.Info.Radius : ", zigbeeLayerData.Info.Radius)
		}

	}
}

func printLorawan() {
	fmt.Println("===== Welcome LoRawan =====")
	lorawanFileHandle, err := pcap.OpenOffline("pcaps/lorawan.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer lorawanFileHandle.Close()

	packetSource := gopacket.NewPacketSource(lorawanFileHandle, LayerTypeLorawan)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(LayerTypeLorawan)
		if layersdata != nil {
			lorawanLayerData, _ := layersdata.(*Lorawan)
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			fmt.Println("lorawan.etherType : ", lorawanLayerData.EthernetType)
			fmt.Println("lorawan.headerData : ", lorawanLayerData.HeaderData)
			fmt.Println("lorawan.Info.Port : ", lorawanLayerData.LorawanInfo.FPort)
			fmt.Println("lorawan.Info.Payload : ", lorawanLayerData.LorawanInfo.FrmPayload)
		}

	}
}

func main() {
	printGoose()
	printBLE()

	// TODO: modbus
	// TODO: mqtt
	// TODO: lorawan

	fmt.Println("======= Done =======")

	printZigbee()
	printLorawan()
}
