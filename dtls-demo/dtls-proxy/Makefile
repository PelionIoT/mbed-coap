EXEC=DTLS-Proxy

CPP=g++
SOURCES=main.cpp DTLSProxy.cpp

CFLAGS += -I/usr/include
LDFLAGS += -lssl -lcrypto

default:
	$(CPP) $(CFLAGS) $(LDFLAGS) $(SOURCES) -o $(EXEC)