

.PHONY: all default bigcoap
all: default bigcoap

default:
	$(MAKE) -f Makefile.default $()

bigcoap:
	$(MAKE) -f Makefile.bigcoap $()

%:
	$(MAKE) -f Makefile.default $@ $()
	$(MAKE) -f Makefile.bigcoap $@ $()
