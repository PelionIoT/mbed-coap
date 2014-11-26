PLATFORM= 
OS = LINUX
TESTCASE = NONE
TARGET	= etsi-server-full_linux
OBJECTS = main.o etsi-server-full_linux.o 
CFLAGS	= -Wall -D_REENTRANT -D$(OS) -I ../../libCoap/src/include -I ../../libNsdl/src/Include  -DHAVE_DEBUG -D$(TESTCASE)
LDFLAGS = -L../../libCoap/x86_gcc/ -L../../libNsdl/x86_gcc/ -D_REENTRANT -lpthread -lNsdl -lCoap 

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	rm *.o
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

