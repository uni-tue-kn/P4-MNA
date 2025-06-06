all: compile start

compile:
	sudo -E ${SDE_INSTALL}/bin/bf-p4c -D__TARGET_TOFINO__=2 --target tofino2-t2na --arch tna2 -o /opt/mna_hbh_preservation mna_hbh_preservation.p4
	sudo -E cp /opt/mna_hbh_preservation/mna_hbh_preservation.conf ${SDE_INSTALL}/share/p4/targets/tofino2/mna_hbh_preservation.conf

start:
	sudo -E ${SDE}/run_switchd.sh -p mna_hbh_preservation --arch tf2