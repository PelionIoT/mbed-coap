PLATFORM= 
OS = LINUX
EDTLS = NO
TARGET	= connected_home_full_oma
OBJECTS = main.o connected_home_full_oma.o 
ifeq ($(EDTLS),NO)
CFLAGS	= -std=c99 -Wall -D_REENTRANT -D$(OS) -I ../../include -I ../../../libService/include -DHAVE_DEBUG
LDFLAGS = -L../../ -D_REENTRANT -lpthread -lnsdl_gcc
endif
ifeq ($(EDTLS),YES)
CFLAGS	= -std=c99 -Wall -D_REENTRANT -D$(OS) -I ../../include -I ../../../libService/include -I ../../libEdtls/src/include -DHAVE_DEBUG -DUSE_EDTLS
LDFLAGS = -L../../ -L../../libEdtls/x86_gcc -D_REENTRANT -lpthread -lnsdl_gcc -leDTLS -lsn_aes
endif

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

