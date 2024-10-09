/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

//== Constants

const bit<16> ETHERTYPE_IPV4 = 0x0800;

typedef bit<48>  EthernetAddress;
typedef bit<32> len_t;

//== Headers

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header modbus_t {
    bit<16> tx_id;
    bit<16> proto_id;
    bit<16> len;
    bit<8>  unit_id;
    bit<1>  fcBit;
    bit<7>  functionCode;
}

struct header_t {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
    modbus_t modbus;
}

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
}

struct ig_metadata_t {
    bit<32> ingress_mac_tstamp; // ingress timestamp
  //  bit<32> fClass_id;          // Function Class ID
  //  bit<32> tx_fc_id;           // Transaction-ID + Function Class
}

struct eg_metadata_t {
    bit<32> modbus_len_val;
    bit<32> dataOffsetValue;
    bit<32> ihlValue;
    bit<32> header_sum;
    bit<32> mbapLen1;
    bit<32> mbapLen2;
}

struct fwd_metadata_t {
    bit<16> hash1;
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

parser TofinoIngressParser(
    packet_in packet,
    inout ig_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser SwitchIngressParser(
    packet_in packet,
    out header_t hdr,
    out ig_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md)
{

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(packet, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
           0x01f6: parse_modbus;
           default: accept;
        }
    }
    state parse_modbus {
        packet.extract(hdr.modbus);
        transition select(hdr.modbus.len) {
          default: accept;
        }
    }
}

//= Pipeline logic

control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action send() {
        /* We hardcode the egress port (all packets towards port 140) */
        ig_intr_tm_md.ucast_egress_port = 140;
    }

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action nop() {
    }

    action ipv4_forward(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    action drop_and_exit(){
            drop();
            exit;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop_and_exit;
        }
        size = 256;
        default_action = drop_and_exit();
    }

    table flowout {
         key = {
                 hdr.ipv4.dstAddr: exact;
                 hdr.ipv4.srcAddr: exact;
                 hdr.ipv4.protocol: exact;
	         hdr.tcp.dstPort: exact;
		         // direction: exact;
                }
         actions = {
		nop;
         }
         size = 256;
         default_action = nop();
     }

     table flowin {
         key = { hdr.ipv4.dstAddr: exact;
                 hdr.ipv4.srcAddr: exact;
                 hdr.ipv4.protocol: exact;
		 hdr.tcp.srcPort: exact;
		         // direction: exact;
                }
         actions = {
		nop;
         }
         size = 256;
         default_action = nop();
     }

    table modbuscheck {
         key = {
		hdr.modbus.functionCode: exact;
                }
         actions = {
		nop;
         }
         size = 256;
         default_action = nop();
     }


     apply {
         ig_md.ingress_mac_tstamp = ig_intr_md.ingress_mac_tstamp[31:0];

         if (hdr.ipv4.isValid()) {

             // valid flow and function code check
             if (!(flowout.apply().hit)) {
                 if (!(flowin.apply().hit)) {
                     if (!(modbuscheck.apply().hit)) {
                         drop_and_exit();
                     }
                 }
             }
             ipv4_lpm.apply();
        }
     }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    // Checksum is not computed yet.

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.modbus);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

struct my_egress_headers_t {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
    modbus_t        modbus;
}

struct my_egress_metadata_t { }


parser SwitchEgressParser(
        packet_in packet,
        out my_egress_headers_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
	packet.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
           0x01f6: parse_modbus;
           default: accept;
        }
    }
    state parse_modbus {
        packet.extract(hdr.modbus);
        transition accept;
    }
}

control SwitchEgress(
        inout my_egress_headers_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {


    action drop() {
            eg_intr_dprs_md.drop_ctl = 0x1; // Drop packet.
    }

    action nop() {
    }

    action drop_and_exit(){
            drop();
            exit;
    }
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_1;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_2;

    #define PACKET_LEN ((bit<32>)eg_intr_md.pkt_length)
    // Action 1: Extract and Cast modbus.len
    action compute_modbus_len_val() {
        eg_md.modbus_len_val = (bit<32>)hdr.modbus.len;
    }

    // Action 2: Compute dataOffsetValue
    action compute_dataOffsetValue() {
        //eg_md.dataOffsetValue = copy32_1.get({26w0 ++ hdr.tcp.dataOffset ++ 2w0});
        bit<4> dataOffVal = hdr.tcp.dataOffset * 4;
        eg_md.dataOffsetValue = (bit<32>)dataOffVal;
    }

    // Action 3: Compute ihlValue
    action compute_ihlValue() {
        eg_md.ihlValue = copy32_2.get({26w0 ++ hdr.ipv4.ihl ++ 2w0});
    }

    // Action 4: Compute header_sum
    action compute_header_sum() {
        eg_md.header_sum=(eg_md.ihlValue + eg_md.dataOffsetValue);
    }

    // Action 5: Compute mbapLen
    action compute_mbapLen1() {
        // Ensure PACKET_LEN is set before this action
        eg_md.mbapLen1 = PACKET_LEN - eg_md.header_sum;
    }
    action compute_mbapLen2() {
        // Ensure PACKET_LEN is set before this action
        eg_md.mbapLen2 = eg_md.mbapLen1 - 32w20;
    }

    apply {
    if(hdr.modbus.isValid()) {
        compute_modbus_len_val();
        compute_dataOffsetValue();
        compute_ihlValue();
        compute_header_sum();
        compute_mbapLen1();
        compute_mbapLen2();

        bool isLengthValid = (eg_md.mbapLen2 == eg_md.modbus_len_val);

        if(!isLengthValid) {
            drop_and_exit();
        }
      }
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout my_egress_headers_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.modbus);
    }
}

//== Switch

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;
