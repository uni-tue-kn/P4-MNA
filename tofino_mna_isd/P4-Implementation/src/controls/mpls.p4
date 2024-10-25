#include "mna.p4"

control MPLS(inout header_t hdr, 
            inout ingress_metadata_t ig_md, 
            inout ingress_intrinsic_metadata_for_tm_t ig_tm_md, 
            in ingress_intrinsic_metadata_t ig_intr_md, 
            inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    MNA() mna_c;

    DirectCounter<bit<32>>(CounterType_t.PACKETS) debug_mpls_counter;

    action drop(){
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action nothing(){
        debug_mpls_counter.count();
    } 

    action mpls_swap_label(bit<20> label) {
        hdr.mpls.label = label;
        hdr.mpls.ttl = hdr.mpls.ttl - 1;
    }

    action mpls_pop_label(){
        hdr.mpls.setInvalid();
    }

    action mpls_pop_last_label(){
        hdr.ethernet.ether_type = ether_type_t.IPV4;
        hdr.ipv4.ttl = hdr.mpls.ttl;

        hdr.mpls.setInvalid();
    }

    action forward(PortId_t port){
        ig_tm_md.ucast_egress_port = port;
        hdr.mpls.ttl = hdr.mpls.ttl - 1;

        debug_mpls_counter.count();
    }

    table mpls_lookup_table {
        key = {
            hdr.mpls.label: exact;
            ig_md.resubmit_needed: exact;
        }
        actions = {
            forward;
            nothing;
        }
        default_action = nothing;
        size = 1024;
        counters = debug_mpls_counter;
    }

    table mpls_table {
        key = { 
            hdr.mpls.label: exact;
            ig_md.resubmit_needed: exact;
        }
        actions = {
            mpls_pop_label;
            mpls_swap_label;
            mpls_pop_last_label;
            drop;
            NoAction;
        }
        default_action = NoAction;
        size = 1024;
    }

    table verify_ttl {
        key = {
            hdr.mpls.ttl: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction;
        size = 256;
    }

    apply {
        mna_c.apply(hdr, ig_md, ig_tm_md, ig_intr_md, ig_dprsr_md);

        if (hdr.mpls.isValid()) {
            verify_ttl.apply();
            mpls_lookup_table.apply();

            // Pop or swap labels
            mpls_table.apply();
        }
    }
}