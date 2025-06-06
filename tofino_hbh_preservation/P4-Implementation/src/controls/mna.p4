#include "mna/mna_first_nas.p4"
#include "mna/mna_second_nas.p4"

control MNA(inout header_t hdr, 
            inout ingress_metadata_t ig_md, 
            inout ingress_intrinsic_metadata_for_tm_t ig_tm_md, 
            in ingress_intrinsic_metadata_t ig_intr_md, 
            inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    MNA_FIRST_NAS() mna_first_nas_c;
    MNA_SECOND_NAS() mna_second_nas_c;

    action drop(){
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action invalidate_first_nas(){
        hdr.mna_nasi.setInvalid();

        hdr.mna_initial_opcode.setInvalid();

        hdr.mna_subsequent_opcodes[0].setInvalid();
        hdr.mna_subsequent_opcodes[1].setInvalid();
        hdr.mna_subsequent_opcodes[2].setInvalid();
        hdr.mna_subsequent_opcodes[3].setInvalid();
        hdr.mna_subsequent_opcodes[4].setInvalid();
        hdr.mna_subsequent_opcodes[5].setInvalid();
        hdr.mna_subsequent_opcodes[6].setInvalid();
        hdr.mna_subsequent_opcodes[7].setInvalid();
        hdr.mna_subsequent_opcodes[8].setInvalid();
        hdr.mna_subsequent_opcodes[9].setInvalid();
        hdr.mna_subsequent_opcodes[10].setInvalid();
        hdr.mna_subsequent_opcodes[11].setInvalid();
        hdr.mna_subsequent_opcodes[12].setInvalid();
        hdr.mna_subsequent_opcodes[13].setInvalid();
        hdr.mna_subsequent_opcodes[14].setInvalid();
    }

    action invalidate_second_nas(){
        hdr.mna_nasi_second_nas.setInvalid();

        hdr.mna_initial_opcode_second_nas.setInvalid();

        hdr.mna_subsequent_opcodes_second_nas[0].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[1].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[2].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[3].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[4].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[5].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[6].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[7].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[8].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[9].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[10].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[11].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[12].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[13].setInvalid();
        hdr.mna_subsequent_opcodes_second_nas[14].setInvalid();
    }

    action set_resubmit(){
        ig_dprsr_md.resubmit_type = 1;
    }

    table mna_scope_first_nas {
        key = {
            hdr.mna_nasi.label: exact;           // Must be 4: NASI
            hdr.mna_initial_opcode.ihs: exact;   // if Select: invalidate
        }
        actions = {
            invalidate_first_nas;
        }
        size = 8;
    }

    table mna_scope_second_nas {
        key = {
            hdr.mna_nasi_second_nas.label: exact;       // TODO remove this?
            hdr.mna_initial_opcode_second_nas.ihs: exact;
        }
        actions = {
            invalidate_second_nas;
        }
        size = 8;
    }

    apply {

        if (ig_md.resubmit.processing_stage == 0 && hdr.mna_initial_opcode.isValid()){
            // Processing stage 0, packet seen for the first time
            mna_first_nas_c.apply(hdr, ig_md, ig_tm_md, ig_intr_md, ig_dprsr_md);
        }
        else if (ig_md.resubmit.processing_stage == 1 || (ig_md.resubmit.processing_stage == 0 && hdr.mna_initial_opcode_second_nas.isValid())){
            // Processing stage 1, either after resubmit, or if no first NAS was present
            mna_second_nas_c.apply(hdr, ig_md, ig_tm_md, ig_intr_md, ig_dprsr_md);
        }

        if (ig_md.resubmit_needed == 1){
            // This packet will be resubmitted to process the second NAS
            set_resubmit();
        } else {

            // Invalidate select scopes, keep HBH scopes
            mna_scope_first_nas.apply();
            mna_scope_second_nas.apply();

            /*
            if (hdr.i2e_bridge.number_of_shifted_mpls_labels == 0){
                // We always shift one label
                hdr.i2e_bridge.number_of_shifted_mpls_labels = 1;
                hdr.i2e_bridge.do_hbh_preservation = 1;
            }
            */
            
            // Aggregate number of labels to shift from first NAS before resubmit and from second NAS.
            bit<8> shift_labels = ig_md.resubmit.shift_labels_first_nas + ig_md.shift_labels_second_nas;
            hdr.i2e_bridge.number_of_shifted_mpls_labels = shift_labels;

            // If HBH preservation action present in second NAS, it is set directly in the action.
            // If it is set in the first NAS, we overwrite it here from resubmit data.
            if (ig_md.resubmit.do_hbh_preservation_first_nas == 1) {
                hdr.i2e_bridge.do_hbh_preservation = 1;
            }
            //bit<1> do_hbh_preservation = ig_md.resubmit.do_hbh_preservation_first_nas | hdr.i2e_bridge.do_hbh_preservation;

            //hdr.i2e_bridge.do_hbh_preservation_first_nas = ig_md.resubmit.do_hbh_preservation_first_nas;
            //hdr.i2e_bridge.do_hbh_preservation = do_hbh_preservation; //ig_md.do_hbh_preservation_second_nas;
        }
    }
}