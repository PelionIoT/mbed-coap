PLATFORM= 
OS = LINUX
EDTLS = NO
TARGET	= connected_home_full_ipv4
OBJECTS = main.o connected_home_full_ipv4.o 
CFLAGS	= -std=gnu99 -Wall -D_REENTRANT -D$(OS) -I ../../include -I ../../../libService/libService -DHAVE_DEBUG
LDFLAGS = -L../../ -D_REENTRANT -lpthread -lnsdl_gcc
ifeq ($(EDTLS),YES)
CFLAGS	+= -I../../../edtls-lib/include -DUSE_EDTLS
LDFLAGS += -L../../../edtls-lib -leDTLS_gcc -L../../../libService -lccm_gcc -laes_gcc -lecc_gcc -llist_gcc -lrand_gcc -lSHA256_gcc -lX509_V3_gcc
endif

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

