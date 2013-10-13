PLATFORM= 
OS = LINUX
EDTLS = NO
TARGET	= connected_home_full_ipv4
OBJECTS = main.o connected_home_full_ipv4.o 
ifeq ($(EDTLS),NO)
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../../libCoap/src/include -I ../../libNsdl/src/Include -DHAVE_DEBUG
LDFLAGS = -L../../libCoap/x86_gcc/  -L../../libNsdl/x86_gcc/ -D_REENTRANT -lpthread -lNsdl -lCoap
endif
ifeq ($(EDTLS),YES)
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../../libCoap/src/include -I ../../libNsdl/src/Include -I ../../libEdtls/src/include -DHAVE_DEBUG -DUSE_EDTLS
LDFLAGS = -L../../libCoap/x86_gcc/ -L../../libNsdl/x86_gcc/ -L../../libEdtls/x86_gcc -D_REENTRANT -lpthread -lCoap -lNsdl -leDTLS -lsn_aes
endif

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

