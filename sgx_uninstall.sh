sudo $SGX_SDK/uninstall.sh

rm sgx_linux_x64_*.bin
rm as.ld.objdump.gold.*.tar.gz
rm -r external

sudo apt-get purge libsgx-launch libsgx-urts libsgx-epid libsgx-quote-ex
sudo apt-get purge libsgx-launch-dbgsym libsgx-urts-dbgsym libsgx-epid-dbgsym libsgx-quote-ex-dbgsym

sudo apt-get autoremove --purge

sudo /opt/intel/sgxdriver/uninstall.sh

sudo rm /usr/local/bin/{as,ld,ld.gold,objdump}

echo Consider doing the appropriate combination of
echo sudo apt-get purge dkms
echo sudo apt-get purge libssl-dev
echo sudo apt-get purge libcurl4-openssl-dev
echo sudo apt-get purge libprotobuf-dev
echo sudo apt-get purge build-essential
echo sudo apt-get purge python