PLATFORM= 
OS = LINUX
EDTLS = NO
TARGET	= connected_home_full_ipv4
OBJECTS = main.o connected_home_full_ipv4.o 
CFLAGS	= -std=gnu99 -Wall -D_REENTRANT -D$(OS) -I ../../libCoap/src/include -I ../../libNsdl/src/Include -I ../../../libService/include -DHAVE_DEBUG
LDFLAGS = -L../../libCoap/x86_gcc/ -L../../libNsdl/x86_gcc/ -D_REENTRANT -lpthread -lNsdl -lCoap
ifeq ($(EDTLS),YES)
CFLAGS	+= -I ../../libEdtls/src/include -DUSE_EDTLS
LDFLAGS += -L../../libEdtls/x86_gcc -leDTLS -laes
endif

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

