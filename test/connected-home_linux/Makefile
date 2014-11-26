PLATFORM= 
OS = LINUX
EDTLS = NO
TARGET	= connected_home
OBJECTS = main.o connected_home.o 
CFLAGS	= -std=gnu99 -Wall -D_REENTRANT -D$(OS) -I ../../libCoap/src/include -I ../../libCoap/src/x86_include -I ../../../libService/include -DHAVE_DEBUG
LDFLAGS = -L../../libCoap/x86_gcc/ -D_REENTRANT -lpthread -lCoap
ifeq ($(EDTLS),YES)
CFLAGS	+= -I ../../libEdtls/src/include -DUSE_EDTLS
LDFLAGS += -L../../libEdtls/x86_gcc -leDTLS -laes
endif

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

