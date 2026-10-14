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
		"tcp_received":          s.TCP.ValidSegmentsReceived.Value(),
		"tcp_invalid":           s.TCP.InvalidSegmentsReceived.Value(),
		"tcp_checksum_errors":   s.TCP.ChecksumErrors.Value(),
		"tcp_sent":              s.TCP.SegmentsSent.Value(),
		"tcp_send_errors":       s.TCP.SegmentSendErrors.Value(),
		"tcp_retransmits":       s.TCP.Retransmits.Value(),
		"tcp_timeouts":          s.TCP.Timeouts.Value(),
		"tcp_resets_received":   s.TCP.ResetsReceived.Value(),
		"tcp_resets_sent":       s.TCP.ResetsSent.Value(),
		"icmp_last_reply_id":    uint64(net.lastEchoID.Load()),
		"icmp_last_reply_ms":    uint64(net.lastEchoMillis.Load()),
	}
}
