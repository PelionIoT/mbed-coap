# ==========================================
#   Unity Project - A Test Framework for C
#   Copyright (c) 2007 Mike Karlesky, Mark VanderVoord, Greg Williams
#   [Released under MIT License. Please refer to license.txt for details]
# ========================================== 

C_COMPILER=gcc
TARGET_BASE=test_libNsdl
TARGET_EXTENSION=.out

TARGET = $(TARGET_BASE)$(TARGET_EXTENSION)

SRC_FILES=../../../unittest/src/unity.c ../../libNsdl/src/sn_grs.c ../../libNsdl/src/sn_nsdl.c \
../../../libService/libList/ns_list.c Test.c  Test_Runner.c

INC_DIRS=-I../../../unittest/src -I../../libCoap/src/include/ -I../../../libService/libService -I../../libNsdl/src/Include/

SYMBOLS= -std=c99 -DTEST -DUNITY_EXCLUDE_STDINT_H

LDFLAGS = -L../../libCoap/x86_gcc -lCoap 

CLEANUP = rm -f build/*.o ; rm -f $(TARGET)

all: clean default

default:
	ruby ../../../unittest/auto/generate_test_runner.rb Test.c  Test_Runner.c
	$(C_COMPILER) $(INC_DIRS) $(SYMBOLS) $(SRC_FILES) -o $(TARGET) $(LDFLAGS)
	./$(TARGET)

clean:
	$(CLEANUP)
	
