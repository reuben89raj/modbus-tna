/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

//== Constants

const bit<16> ETHERTYPE_IPV4 = 0x0800;
//const bit<32> UPPERLIMIT = 0x411B;

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
    modbus_t         modbus;
}

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
}

struct ig_metadata_t {
}

struct eg_metadata_t {
    // Length Check related
    bit<32> modbus_len_val;
    bit<32> dataOffsetValue;
    bit<32> ihlValue;
    bit<32> header_sum;
    bit<32> mbapLen1;
    bit<32> mbapLen2;

    // Arrival rate related
    bit<32> ingress_mac_tstamp; // ingress timestamp
    bit<32> fClass_id;          // Function Class ID  
    bit<32> tx_fc_id;           // Transaction-ID + Function Class
    bit<32> table_read;
    bit<32> prevArrTime;
    bit<32> diff;
    bit<1> dropFlag;
}

struct fwd_metadata_t {
    bit<16> hash1;
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    fwd_metadata_t fwd_metadata;
}

struct burst_data {
    bit<32> timestamp;
    bit<32> count;
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
    
    bool drop_flag1 = false;
    bool drop_flag2 = false;
    bool drop_flag3 = false;

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

    action set_drop1() {
            drop_flag1=true;
    }

    action set_drop2() {
            drop_flag2=true;
    }

    action set_drop3() {
            drop_flag3=true;
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
        default_action = drop_and_exit;
        const entries={
            (0x0A000101): ipv4_forward(0x84);
            (0x0A000202): ipv4_forward(0x85);
        }
    } 

    table flowout {
         key = { 
                 hdr.ipv4.dstAddr: exact;
                 hdr.ipv4.srcAddr: exact;
                 hdr.ipv4.protocol: exact;
	         hdr.tcp.dstPort: exact;
                }
         actions = {
		nop;
                set_drop1;
         }
         size = 256;
         default_action = set_drop1;
         const entries={
            (0x0A000202, 0x0A000101, 6, 502): nop();
         }
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
        set_drop2;
         }
         size = 256;
         default_action = set_drop2;
         const entries={
            (0x0A000101, 0x0A000202, 6, 502): nop();
         }
     }

    table modbuscheck {
         key = { 
		hdr.modbus.functionCode: exact;
                }
         actions = {
		nop;
                set_drop3;
         }
         size = 256;
         default_action = set_drop3;
         const entries={
            (1): nop();
            (2): nop();
            (4): nop();
            (8): nop();
            (15): nop();
        }
     }


     apply {
        if (hdr.ipv4.isValid()) {
            flowout.apply();
            flowin.apply();
            modbuscheck.apply();

            if (drop_flag1 && drop_flag2) {
                drop();  
            } else if (drop_flag1 || drop_flag2) { 
                if (drop_flag3) {
                    drop();
                } else {
                    ipv4_lpm.apply();
                }
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

    #define RESP_THRESHOLD (3000*1000*1000) // 3 seconds
    #define TIMESTAMP eg_intr_md_from_prsr.global_tstamp[31:0]
    #define UPPERLIMIT 32w16667

    Register<bit<32>, _>(32w65536) prevArr;              // Previous arrival time register
    Register<bit<32>, _>(32w65536) intervalStart;        // Interval start register
    /* Register<bit<32>, _>(32w65536) intervalCount;        // Interval count register
    Register<bit<32>, _>(32w65536) currThreshold;        // EWMA threshold register
    Register<bit<32>, _>(32w65536) txFcStatus;           // Transaction status timestamp register */

    /*RegisterAction<bit<32>, _, bit<32>>(prevArr) prevArr_read= {
        void apply(inout bit<32> value, out bit<32> rv) {    
            rv=0;
            bit<32> in_value;                                          
            in_value = value;     
            
            bool current_entry_empty = in_value==0;

            if(current_entry_empty)
            {
                value=0;
                rv=in_value;
            }
        }                                                              
    };

    // RegisterAction to write arrival time
    RegisterAction<bit<32>, _, bit<32>>(prevArr) prevArr_write = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = 0;
            bit<32> in_value;
            in_value = value;

            bool current_entry_empty = in_value==0;
            
            if(current_entry_empty) {
                value=TIMESTAMP;
                rv=1;
            }
        }
    };

    // RegisterAction to read interval start time
    RegisterAction<bit<32>, _, bit<32>>(intervalStart) intervalStart_read = {
        void apply(inout bit<32> value, out bit<32> rv) {    
            rv=0;
            bit<32> in_value;                                          
            in_value = value;     
            
            bool current_entry_empty = in_value==0;

            if(current_entry_empty)
            {
                value=0;
                rv=in_value;
            }
        }                                                              
    };*/

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

    /* Length check
    Breaking down the following :  

        mbapLen = eg_intr_md.pkt_length - (4 * hdr.ipv4.ihl + 4 * hdr.tcp.dataOffset + 24) 

    into separate actions.

    The '24' at the end is because (for some reason), eg_intr_md.pkt_length returns 4 bytes 
    more than what is shown in wireshark. 
    */

    #define PACKET_LEN ((bit<32>)eg_intr_md.pkt_length)
    // Action 1: Extract and Cast modbus.len
    action compute_modbus_len_val() {
        eg_md.modbus_len_val = (bit<32>)hdr.modbus.len;
    }
    
    // Action 2: Compute dataOffsetValue
    action compute_dataOffsetValue() {
        eg_md.dataOffsetValue = copy32_1.get({26w0 ++ hdr.tcp.dataOffset ++ 2w0});
    }
    
    // Action 3: Compute ihlValue
    action compute_ihlValue() {
        eg_md.ihlValue = copy32_2.get({26w0 ++ hdr.ipv4.ihl ++ 2w0});
    }
    
    // Action 4: Compute header_sum
    action compute_header_sum() {
        eg_md.header_sum=(eg_md.ihlValue + eg_md.dataOffsetValue);
    }
    
    // Action 5: Compute mbapLen1
    action compute_mbapLen1() {
        eg_md.mbapLen1 = PACKET_LEN - eg_md.header_sum;
    }

     // Action 5: Compute mbapLen2
    action compute_mbapLen2() {
        eg_md.mbapLen2 = eg_md.mbapLen1 - 32w24;
    }

    // Actions related to arrival rate check
    // for checking rate of arrival -
    Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32_1;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32_2;

    action compute_funcClass_Id() {
        eg_md.fClass_id = crc32_1.get({
            hdr.ipv4.srcAddr,         // source IP address
            hdr.ipv4.dstAddr,         // destination IP address
            hdr.tcp.dstPort,          // destination TCP port
            hdr.modbus.functionCode    // Modbus function code
        });
    }

    action compute_tx_fc_id() {
        eg_md.tx_fc_id = crc32_2.get({
            hdr.modbus.tx_id,          // Modbus Transaction ID
            hdr.modbus.functionCode    // Modbus function code
        });
    }

    /*action prevArrRead() {
        eg_md.table_read = prevArr_read.execute(eg_md.fClass_id);
    }

    action prevArrWrite() {
        eg_md.table_read = prevArr_write.execute(eg_md.fClass_id);
    }

    action compute_diff() {
        eg_md.diff = eg_intr_md_from_prsr.global_tstamp[31:0] - eg_md.prevArrTime ;
    }*/
        
    #define INTERVAL (1000000)            // Define your time interval (e.g., in microseconds)
    #define PACKETSININTERVAL 2 
    #define isWithinInterval ((TIMESTAMP - t_data.timestamp) <= INTERVAL)
    #define isRateExceeded (t_data.count > PACKETSININTERVAL)

    // Define a Register to track the timestamps and counts
    Register<burst_data, _>(0x1000) intervalReg;

    // Define RegisterAction for processing the burst detection logic
    RegisterAction<burst_data, _, bit<1>>(intervalReg) modbusBurst = {
        void apply(inout burst_data data, out bit<1> dropFlag) {
            dropFlag = 0;  // Default: no drop
            burst_data t_data;
            t_data = data;
 
            if (isWithinInterval) {
                if (isRateExceeded) {
                    dropFlag = 1;  // Drop the packet if burst size exceeds the limit
                }
                data.count = data.count + 1;
            } else {
                data.count = 1;
            }
            // Update the timestamp with the current packet's arrival time
            data.timestamp = TIMESTAMP;
        }
    };

    action exec_intervalReg(){
            eg_md.dropFlag=modbusBurst.execute(eg_md.fClass_id);
    }

    apply {
        if(hdr.modbus.isValid()) {

            compute_modbus_len_val();
            compute_dataOffsetValue();
            compute_ihlValue();
            compute_header_sum();
            compute_mbapLen1();
            compute_mbapLen2();
        
            /* for debugging length values

            hdr.modbus.tx_id = eg_md.mbapLen2[15:0];
            hdr.modbus.proto_id = PACKET_LEN[15:0];
            */

            bool isLengthValid = (eg_md.mbapLen2 == eg_md.modbus_len_val);

            if(!isLengthValid) {
                drop_and_exit();
            }

            if (hdr.tcp.dstPort==502) {
            
                //arrTime = eg_intr_md_from_prsr.global_tstamp[31:0];

                // Compute the hash of (flow+FC) and store it in fClass_id
                compute_funcClass_Id();
                exec_intervalReg();

                if (eg_md.dropFlag==1) {
                    drop_and_exit();
                }
                // Compute the hash of (TcId+FC) and store it in tx_fc_id
                //compute_tx_fc_id();

                // prevArrRead();
                // eg_md.prevArrTime = eg_md.table_read;

                // prevArrWrite();

                //compute_diff();
            
                //bool validDiffStage1 = (eg_md.diff[31:16] == (bit<16>)0x0000); // Process higher bits
                // In the next stage of processing (another if block, for example)
                //bool validDiffStage2 = (eg_md.diff[15:0] < (bit<16>)16667);
                //if (validDiffStage1 && validDiffStage2) {
                 //   drop_and_exit();
                //}
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
