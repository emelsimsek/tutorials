/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
struct meta_t {
    bit<16> tcpLength;
}

struct metadata {
  meta_t meta;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t	 tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	meta.meta.tcpLength = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
	    default: accept;
	}	
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        /*mark_to_drop(standard_metadata);*/
	mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action swap_mac(inout bit<48> src,inout bit<48> dst) {
	bit<48> tmp = src;
	src = dst;
	dst = tmp;
    }

    action swap_ip(inout ip4Addr_t srcAddr, inout ip4Addr_t dstAddr) {
	ip4Addr_t tmp = srcAddr;
	srcAddr = dstAddr;
	dstAddr = tmp;
    }

    action swap_port(inout bit<16> srcPort, inout bit<16> dstPort) {
	bit<16> tmp =srcPort;
	srcPort = dstPort;
	dstPort = tmp;
    }
	
    action send_synack()
    {
	swap_mac(hdr.ethernet.srcAddr, hdr.ethernet.dstAddr);
	swap_ip(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);
	swap_port(hdr.tcp.srcPort, hdr.tcp.dstPort);
        hdr.tcp.flags = 8w0x12;	
	hdr.tcp.ackNo =(bit<32>)(hdr.tcp.seqNo + 32w0x00000001);
	hdr.tcp.seqNo = 32w0x27FBB1F0;
	standard_metadata.egress_spec = standard_metadata.ingress_port;

    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
	if ((hdr.tcp.flags & 8w0b00000010) ==  0) {
	   send_synack();	
	}else{
            ipv4_lpm.apply();
	}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

	 update_checksum_with_payload(
				true,
				{ hdr.ipv4.srcAddr,
				  hdr.ipv4.dstAddr, 
				  8w0, 
				  hdr.ipv4.protocol, 
				  meta.meta.tcpLength, 
				  hdr.tcp.srcPort, 
				  hdr.tcp.dstPort,
				  hdr.tcp.seqNo, 
				  hdr.tcp.ackNo, 
				  hdr.tcp.dataOffset, 
				  hdr.tcp.res, 
				  hdr.tcp.flags, 
				  hdr.tcp.window,
				  hdr.tcp.urgentPtr },
				 hdr.tcp.checksum, 
				 HashAlgorithm.csum16);
				}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

