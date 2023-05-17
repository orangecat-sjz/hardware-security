CPUTYPE=$(shell uname -m)
CSOURCES=dpa.c
CPPSOURCES=
ifeq ($(CPUTYPE), x86_64)
#for 64 bits
	ASMSOURCES=
else
#for 32 bits
	ASMSOURCES=
endif

EXECUTABLE=dpa

OBJECTS=$(CPPSOURCES:.cpp=.o) $(CSOURCES:.c=.o) $(ASMSOURCES:.asm=.o)
# The default linker is gcc. Use ld if you have other requirements 

#for C
CC=gcc 
CFLAGS=-c -Wall -g -O3

#for CPP
CXX=g++ 
CXXFLAGS=-c -Wall -g

#for assembly
AS=nasm

ifeq ($(CPUTYPE), x86_64)
	ASFLAGS=-f elf64
else
	ASFLAGS=-f elf 
endif

#linker
LD=$(CC)
LDFLAGS=-lm


all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(LD) $(LDFLAGS) $(OBJECTS) -o $@

#.cpp.o:
#	$(CXX) $(CFLAGS) $< -o $@

#.c.o:
#	$(CC) $(CFLAGS) $< -o $@

%.o : %.asm
	$(AS) $(ASFLAGS) $< -o $@

clean :
	rm -rf *.o $(EXECUTABLE)
