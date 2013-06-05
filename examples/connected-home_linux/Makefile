PLATFORM= 
OS = LINUX
EDTLS = NO
TARGET	= connected_home
OBJECTS = main.o connected_home.o 
ifeq ($(EDTLS),NO)
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../../libCoap/src/include -I ../../libCoap/src/x86_include -DHAVE_DEBUG
LDFLAGS = -L../../libCoap/x86_gcc/ -D_REENTRANT -lpthread -lCoap
endif
ifeq ($(EDTLS),YES)
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../../libCoap/src/include -I ../../libCoap/src/x86_include -I ../../libEdtls/src/include -DHAVE_DEBUG -DUSE_EDTLS
LDFLAGS = -L../../libCoap/x86_gcc/ -L../../libEdtls/x86_gcc -D_REENTRANT -lpthread -lCoap -leDTLS -lsn_aes
endif

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

