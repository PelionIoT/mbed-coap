PLATFORM= 
OS = LINUX
TARGET	= lighting_full
OBJECTS = main.o lighting_full.o 
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../../include -I ../../../libService/include -std=c99 -DHAVE_DEBUG
LDFLAGS = -L../../ -D_REENTRANT -lpthread -lnsdl_gcc 

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

