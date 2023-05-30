package layers

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type HCIPacketType uint8

// Based on https://software-dl.ti.com/simplelink/esd/simplelink_cc13x2_sdk/1.60.00.29_new/exports/docs/ble5stack/vendor_specific_guide/BLE_Vendor_Specific_HCI_Guide/hci_interface.html#hci-interface-protocol
const (
	Command          HCIPacketType = 0x01
	AsynchronousData HCIPacketType = 0x02
	SynchronousData  HCIPacketType = 0x03
	Event            HCIPacketType = 0x04
	ExtendedCommand  HCIPacketType = 0x09
)

func (t HCIPacketType) String() (s string) {
	switch t {
	case Command:
		s = "Command"
	case AsynchronousData:
		s = "Asynchronous Data"
	case SynchronousData:
		s = "Synchronous Data"
	case Event:
		s = "Event"
	case ExtendedCommand:
		s = "Extended Command"
	default:
		s = "Unknown Package Type"
	}
	return
}

type BLEInfo struct {
	HCIPacketType          string `json:"hci_h4.type"`
	BluetoothDeviceAddress uint16 `json:"bthci_evt.bd_addr"`
}

type BLE struct {
	layers.BaseLayer
	HCIPacketType HCIPacketType
	Info          BLEInfo
}

func (m BLE) LayerType() gopacket.LayerType { return LayerTypeBLE }

// decodeBLE decodes the byte slice into a BLE type.
func decodeBLE(data []byte, p gopacket.PacketBuilder) error {
	b := &BLE{}

	err := b.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(b)
	p.SetApplicationLayer(b)

	return nil
}

func (b *BLE) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// TODO: Validate min data length
	if len(data) < 7 {
		df.SetTruncated()
		return errors.New("BLE < 7 bytes")
	}

	if HCIPacketType(data[0]).String() == "Unknown Package Type" {
		df.SetTruncated()
		return errors.New("Unknown Package Type")
	}

	b.HCIPacketType = HCIPacketType(data[0])
	b.BaseLayer.Payload = data[1:]
	return nil
}

func (h *BLE) Payload() []byte {
	return h.BaseLayer.Payload
}
