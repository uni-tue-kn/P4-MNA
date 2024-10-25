


#ifndef _HEADERS_
#define _HEADERS_

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

enum bit<16> ether_type_t {
    IPV4  = 0x0800,
    MPLS  = 0x8847
}

// MPLS eSPL
enum bit<20> MPLS_eSPL_Types {
    IPv4_EXPLICIT_NULL = 0x0,
    ROUTER_ALERT = 0x1,
    IPv6_EXPLICIT_NULL = 0x2,
    IMPLICIT_NULL = 0x3,
    MNA = 0x4,      // TODO change this to the IANA announced value
    ENTROPY_LABEL_INDICATOR = 0x7,
    GENERIC_ASSOCIATED_CHANNEL = 0x13,
    OAM_ALERT = 0x14,
    EXTENSION = 0x15
}

enum bit<7> MNA_Opcodes {
    FLAG_BASED = 2,
    RANGE_EXTENSION = 127
}

enum bit<2> MNA_Scopes {
    I2E = 0,
    HBH = 1,
    SELECT = 2,
    RESERVED = 3
}

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> diffserv;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t srcAddr;
    ipv4_addr_t dstAddr;
}

header mpls_h {
    bit<20> label;
    bit<3> tc; // traffic class
    bit<1> bos; // bottom of stack
    bit<8> ttl;
}

// Format B
header mna_initial_opcode_h {
    bit<7> opcode;
    bit<13> data;
    bit<1> p_bit;
    bit<2> ihs;     // Scope
    bit<1> bos;     // Bottom Of Stack
    bit<1> unknown_action_handling;
    bit<4> nasl;        // Network action substack length
    bit<3> nal;
}

header mna_subsequent_opcode_h {
    bit<7> opcode;
    bit<16> data;
    bit<1> bos;
    bit<1> unknown_action_handling;
    bit<4> data2;
    bit<3> nal;     // Network action length
}

struct digest_valid_headers_t {
    bit<20> mpls_label;
    bit<16> ether_type;
    bit<20> mna_nasi_label;
    bit<7> mna_initial_opcode;
    bit<20> nasi_second_nas;
    bit<7> mna_initial_opcode_select;
    bit<3> drop_ctl;
    bit<1> recirculation_needed;
    bit<7> hbh_sub_opcode_0_label;
    bit<7> hbh_sub_opcode_7_label;
    bit<7> select_sub_opcode_0_label;
    bit<7> select_sub_opcode_7_label;
    bit<8> processing_stage;
    bit<16> parser_error;
    bit<1> hbh_processing_done;
}

struct digest_pmamm_t {
    bit<32> packets_color_a;
    bit<32> packets_color_b;
    bit<18> flow_identifier;
    PortId_t ingress_port;
    bit<48> timestamp;
}

struct processed_subopcodes_t {
    bit<1> index0;
    bit<1> index1;
    bit<1> index2;
    bit<1> index3;
    bit<1> index4;
    bit<1> index5;
    bit<1> index6;
    bit<1> index7;
    bit<1> index8;
    bit<1> index9;
    bit<1> index10;
    bit<1> index11;
    bit<1> index12;
    bit<1> index13;
    bit<1> index14;
    bit<1> _padding;
}

header resubmit_header_h {
    /*
        Stage 0: Initial, nothing processed
        Stage 1: First NAS is processed, process second NAS
    */
    bit<8> processing_stage;
}


struct header_t {
    ethernet_t   ethernet;
    mpls_h       mpls;
    mpls_h              mna_nasi;
    mna_initial_opcode_h mna_initial_opcode;
    mna_subsequent_opcode_h[16] mna_subsequent_opcodes;
    mpls_h mpls_inbetween_0;
    mpls_h mpls_inbetween_1;
    mpls_h mpls_inbetween_2;
    mpls_h mpls_inbetween_3;
    mpls_h mpls_inbetween_4;
    mpls_h mpls_inbetween_5;
    mpls_h mpls_inbetween_6;
    mpls_h mpls_inbetween_7;
    mpls_h mpls_inbetween_8;
    mpls_h mpls_inbetween_9;
    mpls_h mpls_inbetween_10;
    mpls_h mpls_inbetween_11;
    mpls_h mpls_inbetween_12;
    mpls_h mpls_inbetween_13;
    mpls_h mpls_inbetween_14;
    mpls_h mpls_inbetween_15;
    mpls_h nasi_second_nas;
    mna_initial_opcode_h mna_initial_opcode_second_nas;
    mna_subsequent_opcode_h[16] mna_subsequent_opcodes_second_nas;
    ipv4_t       ipv4;
}

header nasi_with_initial_opcode_h {
    // Container for a NASI and the following initial opcode
    bit<20> label;
    bit<3> tc; // traffic class
    bit<1> bos1; // bottom of stack
    bit<8> ttl;
    bit<7> opcode;
    bit<13> data;
    bit<1> p_bit;
    bit<2> ihs;     // Scope
    bit<1> bos2;     // Bottom Of Stack
    bit<3> res;    
    bit<1> unknown_action_handling;
    bit<4> nasl;        // Network action substack length    
}

struct amm_t {
    bit<8> color;
    bit<32> packets_color_a;
    bit<32> packets_color_b;
    bool active;
    bit<18> flow_identifier;
    bit<8> generate_amm_digest;
}

struct ingress_metadata_t {
    processed_subopcodes_t processed_subopcodes;
    bit<1> resubmit_needed;
    bit<1> bos_reached;
    bit<1> unknown_opcode;
    bit<16> parser_error;
    bit<8> reg_recirc_port_index;
    nasi_with_initial_opcode_h nasi_with_initial_opcode;
    amm_t amm;
    resubmit_header_h resubmit;
}


struct egress_metadata_t {
    bit<1> unknown_action_handling;
}

#endif /* _HEADERS_ */