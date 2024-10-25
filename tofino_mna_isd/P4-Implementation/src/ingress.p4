#include "controls/mpls.p4"

control ingress(
        inout header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    MPLS() mpls_c;

    apply {
        mpls_c.apply(hdr, ig_md, ig_tm_md, ig_intr_md, ig_dprsr_md);

        ig_md.parser_error = ig_prsr_md.parser_err;

        if (ig_md.amm.generate_amm_digest == 1){
            ig_dprsr_md.digest_type = 3;
        } else {
            ig_dprsr_md.digest_type = 2;
        }
        
    }
}
