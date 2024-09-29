/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

//== Constants

const bit<16> ETHERTYPE_IPV4 = 0x0800;

bit <1> MB_FLAG = 0;
Register<bit<32>, bit<1>>(1) timestamp;

register<bit<32>>(65535) intervalStart;
register<bit<32>>(65535) prevArr;
register<bit<32>>(65535) intervalCount;
register<bit<32>>(65535) delayRegister;
//bit<32> delIndex;
typedef bit<48>  EthernetAddress;

//== Headers

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
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

header Tcp_option_end_h {
    bit<8> kind;
}
header Tcp_option_nop_h {
    bit<8> kind;
}
header Tcp_option_ss_h {
    bit<8>  kind;
    bit<32> maxSegmentSize;
}
header Tcp_option_s_h {
    bit<8>  kind;
    bit<24> scale;
}
header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}

header Tcp_option_ts_h {
    bit<8>  kind;
    bit<8>  length;
    bit<32> TSval;
    bit<32> TSecr;
}

header_union Tcp_option_h {
    Tcp_option_end_h  end;
    Tcp_option_nop_h  nop;
    Tcp_option_ss_h   ss;
    Tcp_option_s_h    s;
    Tcp_option_sack_h sack;
    Tcp_option_ts_h ts;
}

// Defines a stack of 10 tcp options
typedef Tcp_option_h[10] Tcp_option_stack;

header Tcp_option_padding_h {
    varbit<256> padding;
}

header modbus_t {
    bit<16> tx_id;
    bit<16> proto_id;
    bit<16> len;
    bit<8>  unit_id;
    bit<1>  fcBit;
    bit<7>  functionCode;
}

struct headers_t {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
    Tcp_option_stack tcp_options_vec;
    Tcp_option_padding_h tcp_options_padding;
    modbus_t modbus;
}

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
}

struct ig_metadata_t {
    bit<32> ingress_mac_tstamp; // ingress timestamp
    bit<32> fClass_id;          // Function Class ID  
    bit<32> tx_fc_id;           // Transaction-ID + Function Class
}

struct eg_metadata_t {
}

struct fwd_metadata_t {
    bit<16> hash1;
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength,
    TcpBadTSOptionLength
}

struct Tcp_option_sack_top
{
    bit<8> kind;
    bit<8> length;
}

struct Tcp_option_ts
{
    bit<8> kind;
    bit<8> length;
//    bit<32> TSval;
//    bit<32> TSecr;
}
// This sub-parser is intended to be apply'd just after the base
// 20-byte TCP header has been extracted.  It should be called with
// the value of the Data Offset field.  It will fill in the @vec
// argument with a stack of TCP options found, perhaps empty.

// Unless some error is detect earlier (causing this sub-parser to
// transition to the reject state), it will advance exactly to the end
// of the TCP header, leaving the packet 'pointer' at the first byte
// of the TCP payload (if any).  If the packet ends before the full
// TCP header can be consumed, this sub-parser will set
// error.PacketTooShort and transition to reject.

parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         out Tcp_option_stack vec,
                         out Tcp_option_padding_h padding
                         )
{
    bit<7> tcp_hdr_bytes_left;

    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        // always true here: 0 <= tcp_hdr_bytes_left <= 40
        transition next_option;
    }
    state next_option {
        transition select(tcp_hdr_bytes_left) {
            0 : accept;  // no TCP header bytes left
            default : next_option_part2;
        }
    }
    state next_option_part2 {
        // precondition: tcp_hdr_bytes_left >= 1
        transition select(b.lookahead<bit<8>>()) {
            0: parse_tcp_option_end;
            1: parse_tcp_option_nop;
            2: parse_tcp_option_ss;
            3: parse_tcp_option_s;
            5: parse_tcp_option_sack;
            8: parse_tcp_option_ts;
        }
    }
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        // TBD: This code is an example demonstrating why it would be
        // useful to have sizeof(vec.next.end) instead of having to
        // put in a hard-coded length for each TCP option.
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition consume_remaining_tcp_hdr_and_accept;
    }
    state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(padding, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
    state parse_tcp_option_nop {
        b.extract(vec.next.nop);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition next_option;
    }
    state parse_tcp_option_ss {
        verify(tcp_hdr_bytes_left >= 5, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 5;
        b.extract(vec.next.ss);
        transition next_option;
    }
    state parse_tcp_option_s {
        verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 4;
        b.extract(vec.next.s);
        transition next_option;
    }
    state parse_tcp_option_sack {
        bit<8> n_sack_bytes = b.lookahead<Tcp_option_sack_top>().length;
        // I do not have global knowledge of all TCP SACK
        // implementations, but from reading the RFC, it appears that
        // the only SACK option lengths that are legal are 2+8*n for
        // n=1, 2, 3, or 4, so set an error if anything else is seen.
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<7>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<7>) n_sack_bytes;
        b.extract(vec.next.sack, (bit<32>) (8 * n_sack_bytes - 16));
        transition next_option;
    }
    state parse_tcp_option_ts {
        verify(tcp_hdr_bytes_left >= 10, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
        b.extract(vec.next.ts);
        transition next_option;
    }
}

parser SwitchIngressParser(
    packet_in packet,
    out headers_t hdr, 
    out my_ingress_metadata_t meta, 
    out ingress_intrinsic_metadata_t ig_intr_md) 
{
    bit <1> MB_FLAG = 0;


    state start {
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
        Tcp_option_parser.apply(packet, hdr.tcp.dataOffset,
                                hdr.tcp_options_vec, hdr.tcp_options_padding);

        // Check for data packet. Data packet is any packet with lenth > IPHeader-Length + TCP-Header-Length and
        // does not have ONLY the ACK flag set in TCP header. ONLY ACK translates to hdr.tcp.ctrl = 0b010000
        if ((hdr.ipv4.totalLen > (bit<16>)hdr.ipv4.ihl + (bit<16>)hdr.tcp.dataOffset) && hdr.tcp.ctrl != 0b010000) {
            MB_FLAG = 1;
        }
        transition select  (MB_FLAG) {
            1 : parse_modbus;
            default: accept;
        }
    }
    state parse_modbus {
        packet.extract(hdr.modbus);
        transition accept;
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
    
    bit<1> direction;

    bit<16> mbapLen;
    bit<32> packet_length;

 //   register<bit<32>>(65535) packetsInWindow;
    bit<32> diff;
    int<32> tDiff;
    bit<32> newThreshold;
    int<46> x;
    int<46> x2;


    action drop() {
            ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action nop() {
    }

    action ipv4_forward(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    action drop_and_exit(){
            drop();exit;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop_and_exit;
        }
        size = 1024;
        default_action = drop_and_exit();
    }

    table flowOut {
         key = { hdr.ipv4.dstAddr: exact;
                 hdr.ipv4.srcAddr: exact;
                 hdr.ipv4.protocol: exact;
		         hdr.tcp.dstPort: exact;
		         // direction: exact;
                }
         actions = {
		nop;
		drop;
         }
         size = 1024;
         default_action = drop_and_exit;
     }

     table flowIn {
         key = { hdr.ipv4.dstAddr: exact;
                 hdr.ipv4.srcAddr: exact;
                 hdr.ipv4.protocol: exact;
		         hdr.tcp.srcPort: exact;
		         // direction: exact;
                }
         actions = {
		nop;
		drop;
         }
         size = 1024;
         default_action = drop_and_exit;
     }

    table modbusCheck {
         key = { hdr.modbus.functionCode: exact;
                }
         actions = {
		nop;
		drop;
         }
         size = 1024;
         default_action = drop_and_exit;
     }


     apply {
         ig_md.ingress_mac_tstamp = ig_intr_md.ingress_mac_tstamp[31:0]

         if (hdr.ipv4.isValid()) {
             ipv4_lpm.apply();

             // valid flow and function code check
             if(!(flowOut.apply().hit || flowIn.apply().hit || modbusCheck.apply().hit)) {
                drop_and_exit();   
             }
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
        pkt.emit(hdr.modbus)
    }
}

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }

}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        inout ig_metadata_t ig_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    apply {
        #define packet_length = eg_intr_md.pkt_length;

        if (hdr.tcp.isValid()) {

            // Check if only TCP ;
            if(hdr.ipv4.totalLen <= ((bit<16>)(4*hdr.ipv4.ihl) + (bit<16>)(4*hdr.tcp.dataOffset))){
                nop();
            } else if(hdr.modbus.isValid()) { // Check if Modbus packet

                // Length check    
                bit<16> totalLenValue = (bit<16>)hdr.ipv4.totalLen;
                bit<16> ihlValue = 4 * (bit<16>)hdr.ipv4.ihl;
                bit<16> dataOffsetValue = 4 * (bit<16>)hdr.tcp.dataOffset;

                mbapLen = (bit<16>)packet_length - (ihlValue + dataOffsetValue + 20);

                if (mbapLen != hdr.modbus.len) {
                    drop_and_exit();
                }
                
            }
        }
                        
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



