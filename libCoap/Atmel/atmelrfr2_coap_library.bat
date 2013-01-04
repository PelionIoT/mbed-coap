@echo off

mkdir c:\atmel_release\
mkdir c:\atmel_release\coap_lib\
mkdir c:\atmel_release\coap_lib\include\

set dest=c:\atmel_release\coap_lib\
copy %CD%\AT256RFR2_libCoap.lib %dest%
set dest=c:\atmel_release\coap_lib\include\
copy %CD%\..\src\include\sn_nsdl.h %dest%
copy %CD%\..\src\include\sn_coap_protocol.h %dest%
copy %CD%\..\src\include\sn_coap_header.h %dest%


