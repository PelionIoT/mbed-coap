#!/bin/bash

NSDL_C_GIT_VERSION=551369814169564eb7010a8669ca81670456051b
EDTLS_GIT_VERSION=c746d6a33d8d798b88e36afa63d28108e8ee5dea
VER="1_12"

# Create folders 
rm -r -f ../developer_release_$VER
mkdir ../developer_release_$VER
mkdir ../developer_release_$VER/NanoStack
mkdir ../developer_release_$VER/NanoStack/cc2530_include
mkdir ../developer_release_$VER/NanoStack/MSP430_include
mkdir ../developer_release_$VER/docs

rm -r -f ../enterprise_release_$VER
mkdir ../enterprise_release_$VER
mkdir ../enterprise_release_$VER/docs
mkdir ../enterprise_release_$VER/libEdtls
mkdir ../enterprise_release_$VER/NanoStack
mkdir ../enterprise_release_$VER/NanoStack/cc2530_include
mkdir ../enterprise_release_$VER/NanoStack/MSP430_include
mkdir ../enterprise_release_$VER/libEdtls
mkdir ../enterprise_release_$VER/libEdtls/src
mkdir ../enterprise_release_$VER/libEdtls/x86_gcc
mkdir ../enterprise_release_$VER/libEdtls/src/include

# Clone git repo to ../../git_temp - folder and checkout correct version
git clone -l git://10.45.3.23/nanomesh/nsdl-c.git ../../git_temp
cd ../../git_temp
git checkout $NSDL_C_GIT_VERSION

# Copy examples
cp -r examples ../nsdl-c/developer_release_$VER
rm -rf ../nsdl-c/developer_release_$VER/examples/etsi-server-full_linux
rm -rf ../nsdl-c/developer_release_$VER/examples/etsi-server_linux

cp -r examples ../nsdl-c/enterprise_release_$VER
rm -rf ../nsdl-c/enterprise_release_$VER/examples/etsi-server-full_linux
rm -rf ../nsdl-c/enterprise_release_$VER/examples/etsi-server_linux

# Build and copy libCoap
cd libCoap/x86_gcc
make
rm -f ../src/*.o
cd ../..

cp -r libCoap ../nsdl-c/enterprise_release_$VER
rm -rf ../nsdl-c/enterprise_release_$VER/libCoap/arm-rtemseabi4.11-gcc
rm -rf ../nsdl-c/enterprise_release_$VER/libCoap/arm-none-eabi_gcc
rm -rf ../nsdl-c/enterprise_release_$VER/libCoap/atmega256rfr2_AS
rm -rf ../nsdl-c/enterprise_release_$VER/libCoap/ATxmega256_AS
rm -rf ../nsdl-c/enterprise_release_$VER/libCoap/atxmega256_iar
rm -rf ../nsdl-c/enterprise_release_$VER/libCoap/cc2530_iar
rm -rf ../nsdl-c/enterprise_release_$VER/.gitignore

cp -r ../nsdl-c/enterprise_release_$VER/libCoap ../nsdl-c/developer_release_$VER

rm -f ../nsdl-c/developer_release_$VER/libCoap/src/*.c
rm -f ../nsdl-c/developer_release_$VER/libCoap/src/include/avr_compiler.h
rm -f ../nsdl-c/developer_release_$VER/libCoap/src/include/sn_coap_header_internal.h
rm -f ../nsdl-c/developer_release_$VER/libCoap/src/include/sn_coap_protocol_internal.h
rm -f ../nsdl-c/developer_release_$VER/.gitignore

# Build and copy libNsdl
cd libNsdl/x86_gcc
make
rm -f ../src/*.o
cd ../..

cp -r libNsdl ../nsdl-c/enterprise_release_$VER
rm -rf ../nsdl-c/enterprise_release_$VER/libNsdl/arm-rtemseabi4.11-gcc
rm -rf ../nsdl-c/enterprise_release_$VER/libNsdl/arm-keil
rm -rf ../nsdl-c/enterprise_release_$VER/libNsdl/cc2530_iar

cp -r ../nsdl-c/enterprise_release_$VER/libNsdl ../nsdl-c/developer_release_$VER

rm -f ../nsdl-c/developer_release_$VER/libNsdl/src/*.c
rm -f ../nsdl-c/developer_release_$VER/libNsdl/src/Include/sn_grs.h
rm -f ../nsdl-c/developer_release_$VER/libNsdl/src/Include/sn_linked_list.h

# Remove git_temp 
cd ..
rm -rf git_temp




