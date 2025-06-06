/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2018-2019 Barefoot Networks, Inc.
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 *
 ******************************************************************************/


parser TofinoIngressParser(packet_in pkt,
                            out ingress_metadata_t ig_md,
                            out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        pkt.extract(ig_md.resubmit);
        transition parse_resub_end;
    }

    state parse_resub_end {
#if __TARGET_TOFINO__ != 1
        /* On Tofino-2 and later there are an additional 64 bits of padding
         * after the resubmit data but before the packet headers.  This is also
         * present for non-resubmit packets but the "port_metadata_unpack" call
         * will handle skipping over this padding for non-resubmit packets. */
        pkt.advance(64);
#endif
        transition accept;
    }

    state parse_port_metadata {
        // Advance: Skip over port metadata if you do not wish to use it
        #if __TARGET_TOFINO__ == 2
                pkt.advance(192);
        #else
                pkt.advance(64);
        #endif
                transition accept;
    }
}

parser TofinoEgressParser(packet_in pkt,
                            out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type){
            ether_type_t.IPV4: parse_ipv4;
            ether_type_t.MPLS: parse_mpls;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }    

    state parse_mpls {
        pkt.extract(hdr.mpls);
        transition select (hdr.mpls.bos){
            0x0: continue_mpls_parsing;
            0x1: parse_ipv4;
        }
    }

    state continue_mpls_parsing {
        pkt.extract(hdr.mna_nasi);
        transition select(hdr.mna_nasi.label){
            MPLS_eSPL_Types.MNA: parse_initial_opcode_hbh; // found a NAS
            default: accept;   // No NAS present here
        }
    }

    state parse_initial_opcode_hbh {
        pkt.extract(hdr.mna_initial_opcode);
        // No BoS check needed as a HBH NAS can not be BoS
        transition select(hdr.mna_initial_opcode.nasl){
            0: check_bos_hbh;
            1: parse_nasl_hbh_1;
            2: parse_nasl_hbh_2;
            3: parse_nasl_hbh_3;
            4: parse_nasl_hbh_4;
            5: parse_nasl_hbh_5;
            6: parse_nasl_hbh_6;
            7: parse_nasl_hbh_7;
            8: parse_nasl_hbh_8;
            9: parse_nasl_hbh_9;
            10: parse_nasl_hbh_10;
            11: parse_nasl_hbh_11;
            12: parse_nasl_hbh_12;
            13: parse_nasl_hbh_13;
            14: parse_nasl_hbh_14;
            15: parse_nasl_hbh_15;
        }
    }

        state parse_nasl_hbh_1 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_2 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_3 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_4 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_5 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_6 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_7 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_8 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_9 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_10 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_11 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_12 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_13 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_14 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_15 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_mna_select;
                0x1: parse_ipv4;
            }
        }

    state check_bos_hbh {
        transition select(hdr.mna_initial_opcode.bos){
            0x0: check_mna_select;
            0x1: parse_ipv4;
        }
    }

    state check_mna_select {
        mpls_h next_mpls_label = pkt.lookahead<mpls_h>();

        transition select (next_mpls_label.label){
            MPLS_eSPL_Types.MNA: parse_nasi_second_nas;   // A Select NAS is present, keep going!
            default: parse_next_mpls_segment;        // This is a normal MPLS label, we are done. No Select scope present.
        }
    }

    state parse_nasi_second_nas {
        pkt.extract(hdr.mna_nasi_second_nas);
        transition parse_initial_opcode_select;
    }

    state parse_initial_opcode_select {
        pkt.extract(hdr.mna_initial_opcode_second_nas);
        transition select(hdr.mna_initial_opcode_second_nas.nasl){
            0: check_bos_select;             
            1: parse_nasl_select_1;
            2: parse_nasl_select_2;
            3: parse_nasl_select_3;
            4: parse_nasl_select_4;
            5: parse_nasl_select_5;
            6: parse_nasl_select_6;
            7: parse_nasl_select_7;
            8: parse_nasl_select_8;
            9: parse_nasl_select_9;
            10: parse_nasl_select_10;
            11: parse_nasl_select_11;
            12: parse_nasl_select_12;
            13: parse_nasl_select_13;
            14: parse_nasl_select_14;
            15: parse_nasl_select_15;
        }
    }

    state check_bos_select {
        transition select(hdr.mna_initial_opcode_second_nas.bos){
            0x0: parse_next_mpls_segment;        // We are done
            0x1: parse_ipv4;
        }
    }

        state parse_nasl_select_1 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_2 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_3 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_4 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_5 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_6 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_7 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_8 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }        
        }
        state parse_nasl_select_9 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_10 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_11 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_12 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_13 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_14 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }
        state parse_nasl_select_15 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: parse_next_mpls_segment;
                1: parse_ipv4;
            }
        }

        state parse_next_mpls_segment {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_1;
            }
        }

        state parse_next_mpls_segment_1 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_2;
            }
        }

        state parse_next_mpls_segment_2 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_3;
            }
        }

        state parse_next_mpls_segment_3 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_4;
            }
        }

        state parse_next_mpls_segment_4 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_5;
            }
        }

        state parse_next_mpls_segment_5 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_6;
            }
        }
        state parse_next_mpls_segment_6 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_7;
            }
        }
        state parse_next_mpls_segment_7 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition accept; // RLD reached
            /*
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_8;
            }
            */
        }

        state parse_next_mpls_segment_8 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_9;
            }
        }

        state parse_next_mpls_segment_9 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_10;
            }
        }

        state parse_next_mpls_segment_10 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_11;
            }
        }

        state parse_next_mpls_segment_11 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_12;
            }
        }
        state parse_next_mpls_segment_12 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_13;
            }
        }        
        state parse_next_mpls_segment_13 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_14;
            }
        }    
        state parse_next_mpls_segment_14 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_15;
            }
        }        
        state parse_next_mpls_segment_15 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition accept; // RLD reached
        }                     
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        in ingress_intrinsic_metadata_t ig_intr_md) {


    Digest<digest_valid_headers_t>() digest_valid_headers;

    Resubmit() resubmit;

    apply {

        if (ig_dprsr_md.resubmit_type == 1){
            resubmit.emit(ig_md.resubmit);
        }

        pkt.emit(hdr.i2e_bridge);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.mpls);                      // Forwarding label
        pkt.emit(hdr.mna_nasi);                 // NASI first NAS
        pkt.emit(hdr.mna_initial_opcode);       // init opcode first NAS
        pkt.emit(hdr.mna_subsequent_opcodes);    // sub opcode fist NAS
        pkt.emit(hdr.mna_nasi_second_nas);
        pkt.emit(hdr.mna_initial_opcode_second_nas);
        pkt.emit(hdr.mna_subsequent_opcodes_second_nas);
        pkt.emit(hdr.intermediate_segments_stack);
        pkt.emit(hdr.ipv4);
    }
}


// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_bridge;
    }

    state parse_bridge {
        pkt.extract(hdr.i2e_bridge);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type){
            ether_type_t.MPLS: check_stage;
            default: accept;
        }
    }

    state check_stage {
        transition select(hdr.i2e_bridge.do_hbh_preservation ){
            0: accept;
            1: parse_nas;  // Forwarding label is popped, NAS is exposed to the top, Preserve it
            // TODO use parse_mpls?
        }
    }

    state parse_mpls {
        pkt.extract(hdr.mpls);
        mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
        transition select(next_mpls_label.label, next_mpls_label.bos){
            (MPLS_eSPL_Types.MNA, 0): parse_nas; // We have the HBH NAS at the top (forwarding label was popped)
            (_, 0): parse_next_mpls_segment; 
        }
    }

    state parse_nas {
        // We only get here if we are in processing stage 1/3. So we can safely assume that there is a NAS
        pkt.extract(hdr.mna_nasi);      // NASI
        pkt.extract(hdr.mna_initial_opcode);    // Init opcode
        transition select(hdr.mna_initial_opcode.nasl){
            0: check_bos_after_nas;
            1: parse_nasl_hbh_1;
            2: parse_nasl_hbh_2;
            3: parse_nasl_hbh_3;
            4: parse_nasl_hbh_4;
            5: parse_nasl_hbh_5;
            6: parse_nasl_hbh_6;
            7: parse_nasl_hbh_7;
            8: parse_nasl_hbh_8;
            9: parse_nasl_hbh_9;
            10: parse_nasl_hbh_10;
            11: parse_nasl_hbh_11;
            12: parse_nasl_hbh_12;
            13: parse_nasl_hbh_13;
            14: parse_nasl_hbh_14;
            15: parse_nasl_hbh_15;
        }
    }

    state check_bos_after_nas {
        transition select(hdr.mna_initial_opcode.bos){
            0: parse_next_mpls_segment;
            1: accept;
        }
    }

        state parse_nasl_hbh_1 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }
        }
        state parse_nasl_hbh_2 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_3 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_4 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_5 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_6 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_7 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_8 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_9 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_10 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }

        }
        state parse_nasl_hbh_11 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }
        }
        state parse_nasl_hbh_12 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }
        }
        state parse_nasl_hbh_13 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }
        }
        state parse_nasl_hbh_14 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }
        }
        state parse_nasl_hbh_15 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0: parse_next_mpls_segment;
                1: accept;
            }
        }

        state parse_next_mpls_segment {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_1;
            }
        }

        state parse_next_mpls_segment_1 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_2;
            }
        }

        state parse_next_mpls_segment_2 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_3;
            }
        }

        state parse_next_mpls_segment_3 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_4;
            }
        }

        state parse_next_mpls_segment_4 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_5;
            }
        }

        state parse_next_mpls_segment_5 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_6;
            }
        }
        state parse_next_mpls_segment_6 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition select(hdr.intermediate_segments_stack.last.bos) {
                1: accept;
                0: parse_next_mpls_segment_7;
            }
        }
        state parse_next_mpls_segment_7 {
            pkt.extract(hdr.intermediate_segments_stack.next);
            transition accept; // RLD reached
        }                
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.mpls);
        pkt.emit(hdr.shifted_mpls_segments);
        pkt.emit(hdr.mna_nasi);
        pkt.emit(hdr.mna_initial_opcode);
        pkt.emit(hdr.mna_subsequent_opcodes);
        pkt.emit(hdr.intermediate_segments_stack);
    }
}
