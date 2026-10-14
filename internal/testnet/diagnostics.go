package netstack

// Diagnostics exposes only packet counts from the isolated acceptance stack.
// It contains no packet bodies, ICE credentials or WireGuard configuration.
func (net *Net) Diagnostics() map[string]uint64 {
	s := net.stack.Stats()
	return map[string]uint64{
		"ip_received":           s.IP.PacketsReceived.Value(),
		"ip_valid":              s.IP.ValidPacketsReceived.Value(),
		"ip_malformed":          s.IP.MalformedPacketsReceived.Value(),
		"ip_delivered":          s.IP.PacketsDelivered.Value(),
		"icmp_request_received": s.ICMP.V4.PacketsReceived.EchoRequest.Value(),
		"icmp_reply_received":   s.ICMP.V4.PacketsReceived.EchoReply.Value(),
		"icmp_invalid":          s.ICMP.V4.PacketsReceived.Invalid.Value(),
		"dropped":               s.DroppedPackets.Value(),
	}
}
