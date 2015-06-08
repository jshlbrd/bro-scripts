# Signatures to identify new protocols
# Josh Liburdi 2015

signature protocol_bgp {
	ip-proto == tcp
	payload /^\xff{16}.{2}(\x01|\x02|\x03|\x04|\x05)/
	eval protocol_ident::found
}

signature protocol_ripv1 {
	ip-proto == udp
	payload /^(\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x09|\x0a|\x0b)\x01\x00{2}\x00\x02/
	eval protocol_ident::found
}

signature protocol_ripv2 {
	ip-proto == udp
	payload /^(\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x09|\x0a|\x0b)\x02\x00{2}\x00\x02/
	eval protocol_ident::found
}

signature protocol_vnc {
	ip-proto == tcp
	payload /^RFB\x20/
	eval protocol_ident::found
}
