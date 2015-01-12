PLATFORM= 
OS = LINUX
TARGET	= connected_home_full
OBJECTS = main.o connected_home_full.o 
CFLAGS	= -std=gnu99 -Wall -D_REENTRANT -D$(OS) -I ../../include -I ../../../libService/libService -DHAVE_DEBUG
LDFLAGS = -L../../ -D_REENTRANT -lpthread -lnsdl_gcc 

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

