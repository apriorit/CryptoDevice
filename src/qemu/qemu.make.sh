# git clone https://github.com/qemu/qemu.git
# git checkout stable-2.11
# git patch https://git.qemu.org/?p=qemu.git;a=commitdiff;h=75e5b70e6b5dcc4f2219992d7cffa462aa406af0;hp=200780a3a3ed067dfb2e0d2210b0ed09e748ba26#patch2


cd qemu || exit 1
./configure --target-list=x86_64-softmmu --enable-sdl --enable-debug --extra-ldflags="`pkg-config --libs openssl`" || exit 2
make || exit 3

