PLATFORM= 
OS = LINUX
TARGET	= connected_home_full_oma
OBJECTS = main.o connected_home_full_oma.o 
CFLAGS	+= -I../../include -I../../../libService/libService -I../../../edtls-lib/include -DUSE_EDTLS -std=gnu99 
LDFLAGS += -L../../../edtls-lib -leDTLS_gcc -L../../ -lnsdl_gcc -lpthread
LDFLAGS += -L../../../libService -lccm_gcc -laes_gcc -lecc_gcc -llist_gcc -lrand_gcc -lSHA256_gcc -lX509_V3_gcc

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(PLATFORM)gcc -g -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	
.c.o:
	$(PLATFORM)gcc -c -g -O2 $(CFLAGS) $< 
	
clean:
	rm -f $(TARGET) $(OBJECTS)

