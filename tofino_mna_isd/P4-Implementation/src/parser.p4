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
        ig_md.bos_reached = 1;
        transition accept;
    }

    state parse_mpls {
        pkt.extract(hdr.mpls);
        transition select (hdr.mpls.bos){
            0x0: check_for_first_nas;
            0x1: parse_ipv4;
        }
    }

    // NAS located directly after the first MPLS label
    // ! For the ISD implementation, if two NAS are directly below the first forwarding label,
    // ! the select scoped NAS must be first!
    state check_for_first_nas {
        mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
        transition select(next_mpls_label.label){
            MPLS_eSPL_Types.MNA: parse_initial_opcode_first_nas; // found a NAS
            default: start_hbh_search;
        }
    }

    state parse_initial_opcode_first_nas {
        pkt.extract(hdr.mna_nasi);
        pkt.extract(hdr.mna_initial_opcode);
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
                0x0: check_hbh_already_found;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_2 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_hbh_already_found;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_3 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_hbh_already_found;
                0x1: parse_ipv4;
            }
        }
        state parse_nasl_hbh_4 {
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            pkt.extract(hdr.mna_subsequent_opcodes.next);
            transition select(hdr.mna_subsequent_opcodes.last.bos){
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
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
                0x0: check_hbh_already_found;
                0x1: parse_ipv4;
            }
        }

    state check_hbh_already_found {
        transition select(hdr.mna_initial_opcode.ihs){
            MNA_Scopes.HBH: accept;
            default: start_hbh_search;
        }
    }

    state check_bos_hbh {
        transition select(hdr.mna_initial_opcode.bos){
            0x0: start_hbh_search;
            0x1: parse_ipv4;
        }
    }

    state start_hbh_search {
        // Look at the next MPLS Label
        // Check if it is a NASI
        //  If yes: Lookahead the next two LSE: NASI + initial opcode
        //     - If HBH Scope: Stop search, extract NAS
        //     - else: Check BoS
        //          BoS Reached: accept
        //          Not reached: Continue the search        
        //  If no: Extract it as normal label and check the BoS
        //      BoS Reached: accept
        //      Not reached: Continue the search
        mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
        transition select(next_mpls_label.label){
            MPLS_eSPL_Types.MNA: check_scope_second_nas_0;
            default: check_bos_hbh_search_0;
        }
    }

    state check_bos_hbh_search_0 {
        pkt.extract(hdr.mpls_inbetween_0);
        transition select (hdr.mpls_inbetween_0.bos){
            0: hbh_search_1;
            1: accept;
        }
    }
    state check_scope_second_nas_0 {
        nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
        transition select (nasi_with_initial_opcode.ihs){
            MNA_Scopes.HBH: parse_nasi_second_nas;
            default: check_bos_hbh_search_0;
        }
    }    

        state hbh_search_1 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_1;
                default: check_bos_hbh_search_1;
            }
        }
        state check_bos_hbh_search_1 {
            pkt.extract(hdr.mpls_inbetween_1);
            transition select (hdr.mpls_inbetween_1.bos){
                0: hbh_search_2;
                1: accept;
            }
        }
        state check_scope_second_nas_1 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_1;
            }
        }    
    
        state hbh_search_2 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_2;
                default: check_bos_hbh_search_2;
            }
        }
        state check_bos_hbh_search_2 {
            pkt.extract(hdr.mpls_inbetween_2);
            transition select (hdr.mpls_inbetween_2.bos){
                0: hbh_search_3;
                //0: accept;
                1: accept;
            }
        }
        state check_scope_second_nas_2 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_2;
            }
        }           
    
        state hbh_search_3 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_3;
                default: check_bos_hbh_search_3;
            }
        }
        state check_bos_hbh_search_3 {
            
            pkt.extract(hdr.mpls_inbetween_3);
            transition select (hdr.mpls_inbetween_3.bos){
                0: hbh_search_4;
                1: accept;
            }
        }
        state check_scope_second_nas_3 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_3;
            }
        }        

        state hbh_search_4 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_4;
                default: check_bos_hbh_search_4;
            }
        }
        state check_bos_hbh_search_4 {
            pkt.extract(hdr.mpls_inbetween_4);
            transition select (hdr.mpls_inbetween_4.bos){
                0: hbh_search_5;
                1: accept;
            }
        }
        state check_scope_second_nas_4 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_4;
            }
        }      

        state hbh_search_5 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_5;
                default: check_bos_hbh_search_5;
            }
        }
        state check_bos_hbh_search_5 {
            pkt.extract(hdr.mpls_inbetween_5);
            transition select (hdr.mpls_inbetween_5.bos){
                0: hbh_search_6;
                1: accept;
            }
        }
        state check_scope_second_nas_5 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_5;
            }
        }           
    
        state hbh_search_6 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_6;
                default: check_bos_hbh_search_6;
            }
        }
        state check_bos_hbh_search_6 {
            pkt.extract(hdr.mpls_inbetween_6);
            transition select (hdr.mpls_inbetween_6.bos){
                0: hbh_search_7;
                1: accept;
            }
        }
        state check_scope_second_nas_6 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_6;
            }
        }            
    
        state hbh_search_7 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_7;
                default: check_bos_hbh_search_7;
            }
        }
        state check_bos_hbh_search_7 {
            pkt.extract(hdr.mpls_inbetween_7);
            transition select (hdr.mpls_inbetween_7.bos){
                0: hbh_search_8;
                1: accept;
            }
        }
        state check_scope_second_nas_7 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_7;
            }
        }
        state hbh_search_8 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_8;
                default: check_bos_hbh_search_8;
            }
        }
        state check_bos_hbh_search_8 {
            pkt.extract(hdr.mpls_inbetween_8);
            transition select (hdr.mpls_inbetween_8.bos){
                0: hbh_search_9;
                1: accept;
            }
        }
        state check_scope_second_nas_8 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_8;
            }
        }          
    
        state hbh_search_9 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_9;
                default: check_bos_hbh_search_9;
            }
        }
        state check_bos_hbh_search_9 {
            pkt.extract(hdr.mpls_inbetween_9);
            transition select (hdr.mpls_inbetween_9.bos){
                0: hbh_search_10;
                1: accept;
            }
        }
        state check_scope_second_nas_9 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_9;
            }
        }          
    
        state hbh_search_10 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_10;
                default: check_bos_hbh_search_10;
            }
        }
        state check_bos_hbh_search_10 {
            pkt.extract(hdr.mpls_inbetween_10);
            transition select (hdr.mpls_inbetween_10.bos){
                0: hbh_search_11;
                1: accept;
            }
        }
        state check_scope_second_nas_10 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_10;
            }
        }          
    
        state hbh_search_11 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_11;
                default: check_bos_hbh_search_11;
            }
        }
        state check_bos_hbh_search_11 {
            pkt.extract(hdr.mpls_inbetween_11);
            transition select (hdr.mpls_inbetween_11.bos){
                0: hbh_search_12;
                1: accept;
            }
        }
        state check_scope_second_nas_11 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_11;
            }
        }          
    
        state hbh_search_12 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_12;
                default: check_bos_hbh_search_12;
            }
        }
        state check_bos_hbh_search_12 {
            pkt.extract(hdr.mpls_inbetween_12);
            transition select (hdr.mpls_inbetween_12.bos){
                0: hbh_search_13;
                1: accept;
            }
        }
        state check_scope_second_nas_12 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_12;
            }
        }          
    
        state hbh_search_13 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_13;
                default: check_bos_hbh_search_13;
            }
        }
        state check_bos_hbh_search_13 {
            pkt.extract(hdr.mpls_inbetween_13);
            transition select (hdr.mpls_inbetween_13.bos){
                0: hbh_search_14;
                1: accept;
            }
        }
        state check_scope_second_nas_13 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_13;
            }
        }          
    
        state hbh_search_14 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_14;
                default: check_bos_hbh_search_14;
            }
        }
        state check_bos_hbh_search_14 {
            pkt.extract(hdr.mpls_inbetween_14);
            transition select (hdr.mpls_inbetween_14.bos){
                0: hbh_search_15;
                1: accept;
            }
        }
        state check_scope_second_nas_14 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_14;
            }
        }          
    
        state hbh_search_15 {
            mpls_h next_mpls_label = pkt.lookahead<mpls_h>();
            transition select(next_mpls_label.label){
                MPLS_eSPL_Types.MNA: check_scope_second_nas_15;
                default: check_bos_hbh_search_15;
            }
        }
        state check_bos_hbh_search_15 {
            pkt.extract(hdr.mpls_inbetween_15);
            transition select (hdr.mpls_inbetween_15.bos){
                0: accept; // RLD reached :(
                1: accept;
            }
        }
        state check_scope_second_nas_15 {
            nasi_with_initial_opcode_h nasi_with_initial_opcode = pkt.lookahead<nasi_with_initial_opcode_h>();
            transition select (nasi_with_initial_opcode.ihs){
                MNA_Scopes.HBH: parse_nasi_second_nas;
                default: check_bos_hbh_search_15;
            }
        }                

    state parse_nasi_second_nas {
        pkt.extract(hdr.nasi_second_nas);
        transition parse_initial_opcode_second_nas;
    }

    state parse_initial_opcode_second_nas {
        pkt.extract(hdr.mna_initial_opcode_second_nas);
        // Check if this is the HBH possibly found later in the stack.
        transition select(hdr.mna_initial_opcode_second_nas.ihs){
            MNA_Scopes.HBH: check_nasl_second_nas;
            default: accept;
        }
    }

    state check_nasl_second_nas {
        transition select(hdr.mna_initial_opcode_second_nas.nasl){
            0: check_bos_second_nas;             
            1: parse_nasl_second_nas_1;
            2: parse_nasl_second_nas_2;
            3: parse_nasl_second_nas_3;
            4: parse_nasl_second_nas_4;
            5: parse_nasl_second_nas_5;
            6: parse_nasl_second_nas_6;
            7: parse_nasl_second_nas_7;
            8: parse_nasl_second_nas_8;
            9: parse_nasl_second_nas_9;
            10: parse_nasl_second_nas_10;
            11: parse_nasl_second_nas_11;
            12: parse_nasl_second_nas_12;
            13: parse_nasl_second_nas_13;
            14: parse_nasl_second_nas_14;
            15: parse_nasl_second_nas_15;
        }
    }

    state check_bos_second_nas {
        transition select(hdr.mna_initial_opcode_second_nas.bos){
            0x0: accept;        // We are done
            0x1: parse_ipv4;
        }
    }

        state parse_nasl_second_nas_1 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_2 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_3 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_4 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_5 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_6 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_7 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_8 {
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           pkt.extract(hdr.mna_subsequent_opcodes_second_nas.next);
           transition select(hdr.mna_subsequent_opcodes_second_nas.last.bos) {
                0: accept;
                1: parse_ipv4;
            }        
        }
        state parse_nasl_second_nas_9 {
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
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_10 {
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
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_11 {
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
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_12 {
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
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_13 {
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
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_14 {
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
                0: accept;
                1: parse_ipv4;
            }
        }
        state parse_nasl_second_nas_15 {
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
                0: accept;
                1: parse_ipv4;
            }
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
    Digest<digest_pmamm_t>() digest_pmamm;

    Resubmit() resubmit;

    apply {

        /*
        if (ig_dprsr_md.digest_type == 2){
            digest_valid_headers.pack({
                                        hdr.mpls.label, 
                                        hdr.ethernet.ether_type, 
                                        hdr.mna_nasi.label, 
                                        hdr.mna_initial_opcode.opcode,
                                        hdr.nasi_second_nas.label,
                                        hdr.mna_initial_opcode_second_nas.opcode,
                                        ig_dprsr_md.drop_ctl,
                                        ig_md.recirculation_needed,
                                        hdr.mna_subsequent_opcodes[0].opcode,
                                        hdr.mna_subsequent_opcodes[7].opcode,
                                        hdr.mna_subsequent_opcodes_second_nas[0].opcode,
                                        hdr.mna_subsequent_opcodes_second_nas[7].opcode,
                                        hdr.recirculation_data.processing_stage,
                                        ig_md.parser_error,
                                        ig_md.hbh_processing_done});
        } else*/ if (ig_dprsr_md.digest_type == 3){
            digest_pmamm.pack({
                ig_md.amm.packets_color_a,
                ig_md.amm.packets_color_b,
                ig_md.amm.flow_identifier,
                ig_intr_md.ingress_port,
                ig_intr_md.ingress_mac_tstamp
            });
        }

        if (ig_dprsr_md.resubmit_type == 1){
            resubmit.emit(ig_md.resubmit);
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.mpls);                      // Forwarding label
        pkt.emit(hdr.mna_nasi);                 // First NAS
        pkt.emit(hdr.mna_initial_opcode);       // First NAS
        pkt.emit(hdr.mna_subsequent_opcodes);    // First NAS
        // For some reason in parsing we cannot use a header stack here
        pkt.emit(hdr.mpls_inbetween_0);
        pkt.emit(hdr.mpls_inbetween_1);
        pkt.emit(hdr.mpls_inbetween_2);
        pkt.emit(hdr.mpls_inbetween_3);
        pkt.emit(hdr.mpls_inbetween_4);
        pkt.emit(hdr.mpls_inbetween_5);
        pkt.emit(hdr.mpls_inbetween_6);
        pkt.emit(hdr.mpls_inbetween_7);
        pkt.emit(hdr.mpls_inbetween_8);
        pkt.emit(hdr.mpls_inbetween_9);
        pkt.emit(hdr.mpls_inbetween_10);
        pkt.emit(hdr.mpls_inbetween_11);
        pkt.emit(hdr.mpls_inbetween_12);
        pkt.emit(hdr.mpls_inbetween_13);
        pkt.emit(hdr.mpls_inbetween_14);
        pkt.emit(hdr.mpls_inbetween_15);
        pkt.emit(hdr.nasi_second_nas);
        pkt.emit(hdr.mna_initial_opcode_second_nas);
        pkt.emit(hdr.mna_subsequent_opcodes_second_nas);
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
        transition accept;
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
    Checksum() ipv4_checksum;
    apply {
        if (hdr.ipv4.isValid()){
            hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                    {hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.ecn,
                    hdr.ipv4.total_len,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.frag_offset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr});
        }
    }
}
