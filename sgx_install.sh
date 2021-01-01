VERSION=2.12
DRIVER=sgx_linux_x64_driver_2.11.0_4505f07.bin
SDK=sgx_linux_x64_sdk_2.12.100.3.bin
BUILD_TOOLS_VERSION=r3

UBUNTU_VERSION=20.04
UBUNTU_CODENAME=focal

sudo apt-get install dkms

wget https://download.01.org/intel-sgx/sgx-linux/$VERSION/distro/ubuntu$UBUNTU_VERSION-server/$DRIVER
wget https://download.01.org/intel-sgx/sgx-linux/$VERSION/distro/ubuntu$UBUNTU_VERSION-server/$SDK
wget https://download.01.org/intel-sgx/sgx-linux/$VERSION/as.ld.objdump.gold.$BUILD_TOOLS_VERSION.tar.gz

tar xf as.ld.objdump.gold.$BUILD_TOOLS_VERSION.tar.gz

sudo chown root:root external/toolset/ubuntu$UBUNTU_VERSION/*

sudo mv external/toolset/ubuntu$UBUNTU_VERSION/{as,ld,ld.gold,objdump} /usr/local/bin

chmod +x $DRIVER $SDK

sudo apt-get update
sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev
sudo apt-get install build-essential python-is-python3

sudo ./$DRIVER

echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu $UBUNTU_CODENAME main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install libsgx-launch libsgx-urts libsgx-epid libsgx-quote-ex
sudo apt-get install libsgx-launch-dbgsym libsgx-urts-dbgsym libsgx-epid-dbgsym libsgx-quote-ex-dbgsym

sudo ln -s /usr/lib/x86_64-linux-gnu/libsgx_epid.so.1 /usr/lib/x86_64-linux-gnu/libsgx_epid.so

echo ""
echo ""
echo "#################################################"
echo "#                                               #"
echo "#              Installing SGX SDK               #"
echo "#                                               #"
echo "#################################################"

sudo ./$SDK

echo don\'t forget to
echo 1\) \`sudo chown -R $(whoami) \<sdk/install/path\>\`
echo 2\) add \`source \<sdk/install/path/environment\>\` to your shell\'s startup script
