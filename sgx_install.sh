VERSION=2.10
DRIVER=sgx_linux_x64_driver_2.6.0_602374c.bin
SDK=sgx_linux_x64_sdk_2.10.100.2.bin
BUILD_TOOLS_VERSION=r2

sudo apt-get install dkms

wget https://download.01.org/intel-sgx/sgx-linux/$VERSION/distro/ubuntu18.04-server/$DRIVER
wget https://download.01.org/intel-sgx/sgx-linux/$VERSION/distro/ubuntu18.04-server/$SDK
wget https://download.01.org/intel-sgx/sgx-linux/$VERSION/as.ld.objdump.gold.$BUILD_TOOLS_VERSION.tar.gz

tar xf as.ld.objdump.gold.$BUILD_TOOLS_VERSION.tar.gz

sudo chown root:root external/toolset/ubuntu18.04/*

sudo mv external/toolset/ubuntu18.04/{as,ld,ld.gold,objdump} /usr/local/bin

chmod +x $DRIVER $SDK

sudo apt-get update
sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev
sudo apt-get install build-essential python

sudo ./$DRIVER

echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
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
