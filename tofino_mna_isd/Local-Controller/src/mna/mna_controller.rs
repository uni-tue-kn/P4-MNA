use log::info;
use std::cmp;
use std::{collections::HashMap, hash::Hash, sync::Arc};

use rbfrt::{
    table::MatchValue,
    table::{self, ToBytes},
    SwitchConnection,
};

pub const MPLS_LOOKUP_TABLE: &str = "ingress.mpls_c.mpls_lookup_table";
const DEBUG_DIGEST_NAME: &str = "pipe.SwitchIngressDeparser.digest_valid_headers";
const PMAMM_DIGEST_NAME: &str = "pipe.SwitchIngressDeparser.digest_pmamm";

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct AMMKey {
    port: u32,
    flow_id: u32,
}

#[derive(Clone, Debug)]
pub struct FlowData {
    timestamp: u64,
    color_a: u32,
    color_b: u32,
}

#[derive(Clone, Debug)]
pub struct MNAController {
    mpls_label_to_egress_port_mapping: HashMap<u32, u32>,
    pub amm_data: HashMap<AMMKey, Vec<FlowData>>,
}

impl MNAController {
    pub fn new(mpls_label_to_egress_port_mapping: HashMap<u32, u32>) -> MNAController {
        let amm_data = HashMap::new();
        MNAController {
            mpls_label_to_egress_port_mapping,
            amm_data,
        }
    }

    pub fn init_mpls_lookup(&self) -> Vec<table::Request> {
        let mut table_entries = vec![];

        for (mpls_label, egress_port) in &self.mpls_label_to_egress_port_mapping {
            let tbl_request = table::Request::new(MPLS_LOOKUP_TABLE)
                .match_key("ig_md.resubmit_needed", MatchValue::exact(0))
                .match_key("hdr.mpls.label", MatchValue::exact(*mpls_label))
                .action("ingress.mpls_c.forward")
                .action_data("port", *egress_port);

            table_entries.push(tbl_request);

            let tbl_request = table::Request::new("ingress.mpls_c.mpls_table")
                .match_key("hdr.mpls.label", MatchValue::exact(*mpls_label))
                .match_key("ig_md.resubmit_needed", MatchValue::exact(0))
                .action("ingress.mpls_c.mpls_pop_label");
            table_entries.push(tbl_request);
        }

        table_entries
    }

    pub fn init_constant_entries(&self) -> Vec<table::Request> {
        let mut table_entries = vec![];

        // Drop on 0 TTL
        let tbl_request = table::Request::new("ingress.mpls_c.verify_ttl")
            .match_key("hdr.mpls.ttl", MatchValue::exact(0))
            .action("ingress.mpls_c.drop");
        table_entries.push(tbl_request);

        table_entries
    }

    pub fn init_opcode_entries(&self) -> Vec<table::Request> {
        let mut table_entries = vec![];

        // Initial opcode entries first NAS
        for ad_count in 0..8 {
            let action = format!("ingress.mpls_c.mna_c.mna_first_nas_c.action_initial_with_{ad_count}_ad");
            let tbl_request =
            table::Request::new("ingress.mpls_c.mna_c.mna_first_nas_c.mna_initial_opcode")
                .match_key(
                    "hdr.mna_initial_opcode.opcode",
                    MatchValue::exact(64),
                )
                .match_key(
                    "hdr.mna_initial_opcode.data",
                    MatchValue::ternary(0, 0),
                ) // Ternary match 0,0 is a wildcard match
                .match_key("hdr.mna_initial_opcode.nal", MatchValue::exact(ad_count))
                .action(&action);
            table_entries.push(tbl_request);
        }

        // Initial opcode entries second NAS
        for ad_count in 0..8 {
            let action = format!("ingress.mpls_c.mna_c.mna_second_nas_c.action_initial_with_{ad_count}_ad");
            let tbl_request =
            table::Request::new("ingress.mpls_c.mna_c.mna_second_nas_c.mna_initial_opcode")
                .match_key(
                    "hdr.mna_initial_opcode_second_nas.opcode",
                    MatchValue::exact(64),
                )
                .match_key(
                    "hdr.mna_initial_opcode_second_nas.data",
                    MatchValue::ternary(0, 0),
                ) // Ternary match 0,0 is a wildcard match
                .match_key("hdr.mna_initial_opcode_second_nas.nal", MatchValue::exact(ad_count))
                .action(&action);
            table_entries.push(tbl_request);
        }

        // Default network actions for first NAS
        for network_action_index in 0..14 {
            let control_hbh = "ingress.mpls_c.mna_c.mna_first_nas_c";

            let table_name = format!("{control_hbh}.mna_subsequent_opcode_{network_action_index}");

            let max_ad = cmp::min(15 - network_action_index, 8);

            for ad_count in 0..max_ad {
                let action_name =
                    format!("{control_hbh}.action_{network_action_index}_with_{ad_count}_ad");
                let key1 = format!("hdr.mna_subsequent_opcodes${network_action_index}.opcode");
                let key2 = format!("hdr.mna_subsequent_opcodes${network_action_index}.nal");
                let key3 = format!("hdr.mna_subsequent_opcodes${network_action_index}.data");
                let key4 = format!("hdr.mna_subsequent_opcodes${network_action_index}.data2");

                let tbl_request = table::Request::new(&table_name)
                    .match_key(&key1, MatchValue::exact(64))
                    .match_key(&key2, MatchValue::exact(ad_count))
                    .match_key(&key3, MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                    .match_key(&key4, MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                    .action(&action_name);

                table_entries.push(tbl_request);
            }
        }

        // Default network actions for second NAS
        for network_action_index in 0..14 {
            let control_second_nas = "ingress.mpls_c.mna_c.mna_second_nas_c";

            let table_name =
                format!("{control_second_nas}.mna_subsequent_opcode_{network_action_index}");

            let max_ad = cmp::min(15 - network_action_index, 8);

            for ad_count in 0..max_ad {
                let action_name = format!(
                    "{control_second_nas}.action_{network_action_index}_with_{ad_count}_ad"
                );
                let key1 =
                    format!("hdr.mna_subsequent_opcodes_second_nas${network_action_index}.opcode");
                let key2 =
                    format!("hdr.mna_subsequent_opcodes_second_nas${network_action_index}.nal");
                let key3 =
                    format!("hdr.mna_subsequent_opcodes_second_nas${network_action_index}.data");
                let key4 =
                    format!("hdr.mna_subsequent_opcodes_second_nas${network_action_index}.data2");

                let tbl_request = table::Request::new(&table_name)
                    .match_key(&key1, MatchValue::exact(64))
                    .match_key(&key2, MatchValue::exact(ad_count))
                    .match_key(&key3, MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                    .match_key(&key4, MatchValue::ternary(0, 0)) // Ternary match 0,0 is a wildcard match
                    .action(&action_name);

                table_entries.push(tbl_request);
            }
        }        

        // Network actions for Performance Measurement with AMM
        let control_hbh = "ingress.mpls_c.mna_c.mna_second_nas_c";
        let table_name = format!("{control_hbh}.mna_subsequent_opcode_0");
        let action_name = format!("{control_hbh}.action_0_AMM_color_a_with_0_ad");

        let key1 = format!("hdr.mna_subsequent_opcodes_second_nas$0.opcode"); // Opcode for INT
        let key2 = format!("hdr.mna_subsequent_opcodes_second_nas$0.nal"); // Number of reserved AD entries for path trace
        let key3 = format!("hdr.mna_subsequent_opcodes_second_nas$0.data"); // Flag that specifies to do path tracing
        let key4 = format!("hdr.mna_subsequent_opcodes_second_nas$0.data2"); // Index to identify where to write the Node ID

        let tbl_request = table::Request::new(&table_name)
            .match_key(&key1, MatchValue::exact(43)) // Opcode for PMAMM
            .match_key(&key2, MatchValue::exact(0)) // No AD required
            .match_key(&key3, MatchValue::ternary(2, 2)) // Flow Identifier
            .match_key(&key4, MatchValue::ternary(0, 0)) // Color
            .match_key("$MATCH_PRIORITY", MatchValue::exact(1))
            .action(&action_name);
        table_entries.push(tbl_request);
        let action_name = format!("{control_hbh}.action_0_AMM_color_b_with_0_ad");
        let tbl_request = table::Request::new(&table_name)
            .match_key(&key1, MatchValue::exact(43)) // Opcode for PMAMM
            .match_key(&key2, MatchValue::exact(0)) // No AD required
            .match_key(&key3, MatchValue::ternary(2, 2)) // Flow Identifier
            .match_key(&key4, MatchValue::ternary(2, 2)) // Color
            .match_key("$MATCH_PRIORITY", MatchValue::exact(0))
            .action(&action_name);
        table_entries.push(tbl_request);


        // Network Slicing first NAS
        let tbl_request = table::Request::new("ingress.mpls_c.mna_c.mna_first_nas_c.mna_initial_opcode")
        .match_key("hdr.mna_initial_opcode.opcode", MatchValue::exact(5)) // Opcode for NRP
        .match_key("hdr.mna_initial_opcode.nal", MatchValue::exact(0)) // No AD required
        .match_key("hdr.mna_initial_opcode.data", MatchValue::ternary(0, 0)) // Flow Identifier
            .action("ingress.mpls_c.mna_c.mna_first_nas_c.action_initial_nrp_with_0_ad");
        table_entries.push(tbl_request);   

        // Network Slicing second NAS
        let tbl_request = table::Request::new("ingress.mpls_c.mna_c.mna_second_nas_c.mna_initial_opcode")
            .match_key("hdr.mna_initial_opcode_second_nas.opcode", MatchValue::exact(5)) // Opcode for NRP
            .match_key("hdr.mna_initial_opcode_second_nas.nal", MatchValue::exact(0)) // No AD required
            .match_key("hdr.mna_initial_opcode_second_nas.data", MatchValue::ternary(0, 0)) // Flow Identifier
            .match_key("$MATCH_PRIORITY", MatchValue::exact(0))
            .action("ingress.mpls_c.mna_c.mna_second_nas_c.action_initial_nrp_with_0_ad");
        table_entries.push(tbl_request);        

        /*
        // Drop Actions for AMM evaluation
        let tbl_request = table::Request::new("ingress.probabilistic_packet_drop")
            .match_key("ig_intr_md.ingress_port", MatchValue::exact(152))     // LSR A
            .match_key("ig_md.random_number", MatchValue::range(0, 6553))     // 10% drop chance
            .action("ingress.drop");
        table_entries.push(tbl_request);
        let tbl_request = table::Request::new("ingress.probabilistic_packet_drop")
            .match_key("ig_intr_md.ingress_port", MatchValue::exact(304))     // LSR B
            .match_key("ig_md.random_number", MatchValue::range(0, 13107))     // 20% drop chance
            .action("ingress.drop");
        table_entries.push(tbl_request);
        let tbl_request = table::Request::new("ingress.probabilistic_packet_drop")
            .match_key("ig_intr_md.ingress_port", MatchValue::exact(400))     // LSR C
            .match_key("ig_md.random_number", MatchValue::range(0, 19660))     // 30% drop chance
            .action("ingress.drop");
        table_entries.push(tbl_request);
        let tbl_request = table::Request::new("egress.probabilistic_packet_drop")
            .match_key("eg_intr_md.egress_port", MatchValue::exact(168))     // LSR A
            .match_key("eg_md.random_number", MatchValue::range(0, 307))     // 30% drop chance
            .action("egress.drop");
        table_entries.push(tbl_request);
        */

        table_entries
    }


    pub fn configure_network_slices(&self) -> Vec<table::Request> {
        let mut table_entries = vec![];

        let req = table::Request::new("ingress.mpls_c.mna_c.network_slicing")
            .match_key("ig_md.nrp.identifier", MatchValue::exact(100))
            .action("ingress.mpls_c.mna_c.set_color_direct")
            .action_data("$METER_SPEC_CIR_KBPS", 20005000)
            .action_data("$METER_SPEC_PIR_KBPS", 20005001)
            .action_data("$METER_SPEC_CBS_KBITS", 1000)
            .action_data("$METER_SPEC_PBS_KBITS", 2000);
        table_entries.push(req); 

        let req = table::Request::new("ingress.mpls_c.mna_c.network_slicing")
            .match_key("ig_md.nrp.identifier", MatchValue::exact(200))
            .action("ingress.mpls_c.mna_c.set_color_direct")
            .action_data("$METER_SPEC_CIR_KBPS", 30005000)
            .action_data("$METER_SPEC_PIR_KBPS", 30005001)
            .action_data("$METER_SPEC_CBS_KBITS", 1000)
            .action_data("$METER_SPEC_PBS_KBITS", 2000);
        table_entries.push(req); 

        let req = table::Request::new("ingress.mpls_c.mna_c.network_slicing")
            .match_key("ig_md.nrp.identifier", MatchValue::exact(300))
            .action("ingress.mpls_c.mna_c.set_color_direct")
            .action_data("$METER_SPEC_CIR_KBPS", 50005000)
            .action_data("$METER_SPEC_PIR_KBPS", 50005001)
            .action_data("$METER_SPEC_CBS_KBITS", 1000)
            .action_data("$METER_SPEC_PBS_KBITS", 2000);
        table_entries.push(req);      

        let req = table::Request::new("ingress.mpls_c.mna_c.network_slicing")
            .match_key("ig_md.nrp.identifier", MatchValue::exact(400))
            .action("ingress.mpls_c.mna_c.set_color_direct")
            .action_data("$METER_SPEC_CIR_KBPS", 1000)
            .action_data("$METER_SPEC_PIR_KBPS", 1001)
            .action_data("$METER_SPEC_CBS_KBITS", 1000)
            .action_data("$METER_SPEC_PBS_KBITS", 2000);
        table_entries.push(req);                      

        table_entries
    }

    pub async fn digest_monitor(&mut self, switch: Arc<SwitchConnection>) {
        info!("Starting listening for digests");
        while let Ok(digest) = &mut switch.digest_queue.recv() {
        if digest.name == PMAMM_DIGEST_NAME {
                let data = &digest.data;
                let packets_color_a = data.get("packets_color_a").unwrap().to_u32();
                let packets_color_b: u32 = data.get("packets_color_b").unwrap().to_u32();
                let ingress_port = data.get("ingress_port").unwrap().to_u32();
                let flow_identifier = data.get("flow_identifier").unwrap().to_u32();
                let timestamp = data.get("timestamp").unwrap().to_u64();

                let flow_data = FlowData {
                    timestamp: timestamp,
                    color_a: packets_color_a,
                    color_b: packets_color_b,
                };
                let amm_key = AMMKey {
                    port: ingress_port,
                    flow_id: flow_identifier,
                };

                let data = self
                    .amm_data
                    .entry(amm_key)
                    .or_insert(vec![flow_data.clone()]);
                data.push(flow_data);

                info!("PMAMM counters received from port {}, flow_id: {},  Color A: {}, Color B: {}, timestamp: {}", ingress_port, flow_identifier, packets_color_a, packets_color_b, timestamp);
            }
        }
    }
}
