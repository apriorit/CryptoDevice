TAP=tap0
./qemu/x86_64-softmmu/qemu-system-x86_64 \
	-enable-kvm \
	-m 2G \
	-cpu host \
	-smp cpus=4,cores=4,threads=1,sockets=1 \
	-device pci-crypto,aes_cbc_256=secret \
	-hda /home/windows10.x64.img \
	-device e1000,netdev=network0 -netdev tap,id=network0,ifname=$TAP,script=no,downscript=no \
	-snapshot 


#	-net nic,macaddr=52:54:01:23:34:44 -net tap,ifname=$TAP 
#	-snapshot 




