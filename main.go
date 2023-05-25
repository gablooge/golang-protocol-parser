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

func printModbusTcp() {
	fmt.Println("==== Welcome Modbus TCP ====")
	modbustcpFileHandle, err := pcap.OpenOffline("pcaps/modbustcp.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer modbustcpFileHandle.Close()

	packetSource := gopacket.NewPacketSource(modbustcpFileHandle, LayerTypeModbusTCP)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(LayerTypeModbusTCP)
		if layersdata != nil {
			modbusLayerData, _ := layersdata.(*ModbusTCP)
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			fmt.Println("modbustcp.TransactionIdentifier : ", modbusLayerData.TransactionIdentifier)
			fmt.Println("modbustcp.ProtocolIdentifier : ", modbusLayerData.ProtocolIdentifier)
			fmt.Println("modbustcp.UnitIdentifier : ", modbusLayerData.UnitIdentifier)
			fmt.Println("modbustcp.Data : ", modbusLayerData.Data)
		}

	}
}

func printModbusUdp() {
	fmt.Println("==== Welcome Modbus UDP ====")
	modbustcpFileHandle, err := pcap.OpenOffline("pcaps/mbudp.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer modbustcpFileHandle.Close()

	packetSource := gopacket.NewPacketSource(modbustcpFileHandle, LayerTypeModbusUdp)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(LayerTypeModbusUdp)
		if layersdata != nil {
			modbusLayerData, _ := layersdata.(*ModbusUdp)
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			// fmt.Println("print ", modbusLayerData.BaseLayer)
			fmt.Println("modbustcp.TransactionIdentifier : ", modbusLayerData.Info.TransId)
			fmt.Println("modbustcp.ProtocolIdentifier : ", modbusLayerData.Info.ProtId)
			fmt.Println("modbustcp.UnitIdentifier : ", modbusLayerData.Info.UnitId)
			fmt.Println("modbustcp.ReferenceNumber : ", modbusLayerData.Info.ReferenceNum)
			fmt.Println("modbustcp.WordCount : ", modbusLayerData.Info.WordCnt)
			fmt.Println("modbustcp.CannotClassify : ", modbusLayerData.Info.CannotClassify)
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
	printLorawan()
	printModbusTcp()
	// printModbusUdp()
}
