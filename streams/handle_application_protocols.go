package streams

import (
	"sort"
)

type ApplicationProtocol string

//nolint:godot // We want to comment code out, not write sentences
const (
	// Layers
	ApplicationProtocolGOOSE  ApplicationProtocol = "goose"
	ApplicationProtocolBLE    ApplicationProtocol = "ble"
	ApplicationProtocolModbus ApplicationProtocol = "modbus"
	ApplicationProtocolDNP3   ApplicationProtocol = "dnp3"
	// ApplicationProtocolCAN    ApplicationProtocol = "can"
	// Streams
	ApplicationProtocolHTTP ApplicationProtocol = "http"
	ApplicationProtocolSSH  ApplicationProtocol = "ssh"
	ApplicationProtocolTLS  ApplicationProtocol = "tls"
	// ApplicationProtocolFTP  ApplicationProtocol = "ftp"
	// ApplicationProtocolMQTT  ApplicationProtocol = "mqtt"
)

// ApplicationProtocolAll lists all supported application protocols.
var ApplicationProtocolAll = []ApplicationProtocol{
	ApplicationProtocolGOOSE,
	ApplicationProtocolHTTP,
	ApplicationProtocolSSH,
	ApplicationProtocolTLS,
}

// ApplicationProtocolSlice attaches the methods of Interface to []string, sorting in increasing order.
type ApplicationProtocolSlice []ApplicationProtocol

func (x ApplicationProtocolSlice) Len() int           { return len(x) }
func (x ApplicationProtocolSlice) Less(i, j int) bool { return x[i] < x[j] }
func (x ApplicationProtocolSlice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

// Sort is a convenience method: x.Sort() calls Sort(x).
func (x ApplicationProtocolSlice) Sort() { sort.Sort(x) }

func (x ApplicationProtocolSlice) Strings() []string {
	tr := []string{}
	for _, ap := range x {
		tr = append(tr, string(ap))
	}

	return tr
}

func applicationProtocolsFromStream(stream Stream) []ApplicationProtocol {
	if stream == nil {
		return nil
	}

	if _, ok := stream.(*HTTP); ok {
		return []ApplicationProtocol{ApplicationProtocolHTTP}
	} else if _, ok := stream.(*DNP3); ok {
		return []ApplicationProtocol{ApplicationProtocolDNP3}
	}

	return nil
}
