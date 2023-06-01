package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"go.uber.org/zap"

	"samsulhadi.com/go-packet-parser/layers"
	"samsulhadi.com/go-packet-parser/streams"
)

func printGoose() {
	fmt.Println("======= Welcome Goose =======")

	gooseFileHandle, err := pcap.OpenOffline("pcaps/goose.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer gooseFileHandle.Close()

	packetSource := gopacket.NewPacketSource(gooseFileHandle, layers.LayerTypeGOOSE)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(layers.LayerTypeGOOSE)
		if layersdata != nil {
			gooseLayerData, _ := layersdata.(*layers.GOOSE)
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

	bleFileHandle, err := pcap.OpenOffline("pcaps/ble.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer bleFileHandle.Close()

	packetSource := gopacket.NewPacketSource(bleFileHandle, layers.LayerTypeBLE)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(layers.LayerTypeBLE)
		if layersdata != nil {
			bleLayerData, _ := layersdata.(*layers.BLE)
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

	packetSource := gopacket.NewPacketSource(lorawanFileHandle, layers.LayerTypeLorawan)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(layers.LayerTypeLorawan)
		if layersdata != nil {
			lorawanLayerData, _ := layersdata.(*layers.Lorawan)
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
	modbustcpFileHandle, err := pcap.OpenOffline("pcaps/modbustcp.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer modbustcpFileHandle.Close()

	packetSource := gopacket.NewPacketSource(modbustcpFileHandle, layers.LayerTypeModbusTCP)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(layers.LayerTypeModbusTCP)
		if layersdata != nil {
			modbusLayerData, _ := layersdata.(*layers.ModbusTCP)
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			fmt.Println("modbustcp.TransactionIdentifier : ", modbusLayerData.TransactionIdentifier)
			fmt.Println("modbustcp.ProtocolIdentifier : ", modbusLayerData.ProtocolIdentifier)
			fmt.Println("modbustcp.ModbusTCPInfo.UnitIdentifier : ", modbusLayerData.ModbusTCPInfo.UnitIdentifier)
			fmt.Println("modbustcp.ModbusTCPInfo.FuncCode : ", modbusLayerData.ModbusTCPInfo.FuncCode)
			fmt.Println("modbustcp.ModbusTCPInfo.Data : ", modbusLayerData.ModbusTCPInfo.Data)
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

	packetSource := gopacket.NewPacketSource(modbustcpFileHandle, layers.LayerTypeModbusUdp)

	i := 0
	// Loop through packets in file
	for packet := range packetSource.Packets() {
		layersdata := packet.Layer(layers.LayerTypeModbusUdp)
		if layersdata != nil {
			modbusLayerData, _ := layersdata.(*layers.ModbusUdp)
			i = i + 1
			fmt.Println("======= Packet " + strconv.Itoa(i) + " =======")
			// fmt.Println("print ", modbusLayerData.BaseLayer)
			fmt.Println("modbusudp.TransactionIdentifier : ", modbusLayerData.ModbusUDPInfo.TransId)
			fmt.Println("modbusudp.ProtocolIdentifier : ", modbusLayerData.ModbusUDPInfo.ProtId)
			fmt.Println("modbusudp.UnitIdentifier : ", modbusLayerData.ModbusUDPInfo.UnitId)
			fmt.Println("modbusudp.ReferenceNumber : ", modbusLayerData.ModbusUDPInfo.ReferenceNum)
			fmt.Println("modbusudp.WordCount : ", modbusLayerData.ModbusUDPInfo.WordCnt)
			fmt.Println("modbusudp.CannotClassify : ", modbusLayerData.ModbusUDPInfo.CannotClassify)
		}

	}
}

func printStream(pcalFile string) {
	logLevel := zap.LevelFlag(
		"log-level",
		zap.DebugLevel,
		"set the global minimum logging level",
	)
	// set up loggers
	loggerConfig := zap.NewProductionConfig()
	loggerConfig.Level.SetLevel(*logLevel)
	loggerConfig.Encoding = "console"
	loggerConfig.EncoderConfig = zap.NewDevelopmentEncoderConfig()

	logger, _ := loggerConfig.Build()
	ReassemblyPool := streams.NewReassemblyPool(logger.Named("reassembly"))
	configHandle_logger := logger.Named("handle")

	assembler := reassembly.NewAssembler(ReassemblyPool)
	handle, err := pcap.OpenOffline(pcalFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		streams.HandleReassembly(configHandle_logger, assembler, packet)
	}
	assembler.FlushAll()
}

func main() {
	// TODO: mqtt
	// TODO: lorawan

	// printGoose()
	// printBLE()
	// printLorawan()
	// printModbusUdp()
	// printStream("pcaps/http.pcap")
	printStream("pcaps/modbustcp.pcap")

	// TODO: add printStream("pcaps/tpkt.pcap")
	// TODO: add printStream("pcaps/copt.pcap")
	// TODO: add printStream("pcaps/mms.pcap")
	// TODO: add printStream("pcaps/IEC60870-5.pcap")
	// TODO: add printStream("pcaps/DNP3.pcap")
	fmt.Println("======= Done =======")
}
