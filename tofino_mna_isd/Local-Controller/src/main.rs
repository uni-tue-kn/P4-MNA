/* Copyright 2022-present University of Tuebingen, Chair of Communication Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use log::{info, warn};
use rbfrt::register::Register;
use rbfrt::util::port_manager::{AutoNegotiation, Loopback, Port, Speed, FEC};
use rbfrt::util::{PortManager, PrettyPrinter};
use rbfrt::{register, table, SwitchConnection};

mod mna;
use mna::MNAController;

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    info!("Start controller...");

    let mut switch = SwitchConnection::new("localhost", 50052)
        .device_id(0)
        .client_id(1)
        .p4_name("mna_isd")
        .connect()
        .await?;

    switch.clear_table("$PORT").await?;

    let pm = PortManager::new(&mut switch).await;

    let mut port_requests: Vec<Port> = vec![];

    // Configure ports here as needed
    let pm_req = Port::new(5, 0).speed(Speed::BF_SPEED_400G).fec(FEC::BF_FEC_TYP_REED_SOLOMON);
    port_requests.push(pm_req);    

    pm.add_ports(&mut switch, &port_requests).await?;

    info!("Ports of device configured.");

    // Mapping of (mpls_label, egress_dev_port)
    let mpls_label_to_egress_port_mapping = HashMap::from([
        (50, 168),
        (60, 168),
        (500, 136), // Used for AMM eval chain
        (600, 296), // Used for AMM eval chain
        (700, 168), // Used for AMM eval chain
        (800, 152), // Used for AMM eval chain
        (301, 152), // Used for NRPs
    ]);
    let mut mna_controller = MNAController::new(mpls_label_to_egress_port_mapping);

    let tables: Vec<&str> = vec![
        mna::mna_controller::MPLS_LOOKUP_TABLE,
        "ingress.mpls_c.verify_ttl",
        "ingress.mpls_c.mpls_table",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_0",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_1",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_2",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_3",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_4",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_5",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_6",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_7",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_8",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_9",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_10",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_11",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_12",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_13",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_subsequent_opcode_14",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_0",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_1",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_2",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_3",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_4",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_5",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_6",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_7",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_8",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_9",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_10",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_11",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_12",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_subsequent_opcode_13",
        "ingress.mpls_c.mna_c.mna_first_nas_c.mna_initial_opcode",
        "ingress.mpls_c.mna_c.mna_second_nas_c.mna_initial_opcode",
        "ingress.mpls_c.mna_c.amm_packet_loss_counter_color_a",
        "ingress.mpls_c.mna_c.amm_packet_loss_counter_color_b",
        "ingress.mpls_c.mna_c.amm_packet_loss_last_color",
        "ingress.mpls_c.mna_c.network_slicing"
    ];

    switch.clear_tables(tables).await;

    let mut table_entries = mna_controller.init_mpls_lookup();
    table_entries.extend(mna_controller.init_constant_entries());
    table_entries.extend(mna_controller.init_opcode_entries());
    table_entries.extend(mna_controller.configure_network_slices());

    switch.write_table_entries(table_entries).await?;

    let switch = Arc::new(switch);
    let switch2 = Arc::clone(&switch);

    tokio::spawn(async move {
        mna_controller.digest_monitor(switch2).await;
    });

    let pp = PrettyPrinter::new();

    loop {
        // Read tables for debugging
        let table_to_check = "ingress.mpls_c.mna_c.mna_second_nas_c.mna_initial_opcode";
        let sync =
            table::Request::new(table_to_check).operation(table::TableOperation::SyncCounters);

        if switch.execute_operation(sync).await.is_err() {
            warn! {"Encountered error while synchronizing {}.", table_to_check};
        }

        let req: table::Request = table::Request::new(table_to_check);

        let res = switch.get_table_entry(req).await?;

        pp.print_table(res)?;

        /*
        // Read AMM registers for debugging
        let mut requests = vec![];
        requests.push(
            register::Request::new("ingress.mpls_c.mna_c.amm_packet_loss_counter_color_a").index(8),
        );

        let sync = table::Request::new("ingress.mpls_c.mna_c.amm_packet_loss_counter_color_a")
            .operation(table::TableOperation::SyncRegister);
        if switch.execute_operation(sync).await.is_err() {
            warn!(
                "Error in synchronization for register {}.",
                "ingress.mpls_c.mna_c.amm_packet_loss_counter_color_a"
            );
        }
        let fut = switch.get_register_entries(requests.clone()).await;
        info!("{:?}", fut);
        */

        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> () {
    env_logger::init();

    match run().await {
        Ok(_) => {}
        Err(e) => {
            warn!("Error: {}", e);
        }
    }
}
