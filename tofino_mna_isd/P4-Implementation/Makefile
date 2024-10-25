all: compile start

compile:
	sudo -E ${SDE_INSTALL}/bin/bf-p4c -D__TARGET_TOFINO__=2 --target tofino2-t2na --arch tna2 -o /opt/mna_isd mna_isd.p4
	sudo -E cp /opt/mna_isd/mna_isd.conf ${SDE_INSTALL}/share/p4/targets/tofino2/mna_isd.conf

start:
	sudo -E ${SDE}/run_switchd.sh -p mna_isd --arch tf2
