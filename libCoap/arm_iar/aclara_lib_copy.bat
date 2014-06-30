
mkdir %1\..\..\..\Aclara_Node_Project\ARM_Libraries\
mkdir %1\..\..\..\Aclara_Node_Project\ARM_Libraries\Include\nsdl
mkdir %1\..\..\..\Aclara_Node_Project\ARM_Libraries\Binary
copy %1\*.a %1\..\..\..\Aclara_Node_Project\ARM_Libraries\Binary\

copy %1\..\src\include\sn_coap_header.h %1\..\..\..\Aclara_Node_Project\ARM_Libraries\Include\nsdl
copy %1\..\src\include\sn_coap_protocol.h %1\..\..\..\Aclara_Node_Project\ARM_Libraries\Include\nsdl
copy %1\..\src\include\sn_nsdl.h %1\..\..\..\Aclara_Node_Project\ARM_Libraries\Include\nsdl
