.PHONY: all pre install

MAJOR ?= $(shell major=$$(grep MAJOR include/revision.h);major=$${major#*\"};major=$${major%%\"*};echo $$major)
MINOR ?= $(shell minor=$$(grep MINOR include/revision.h);minor=$${minor#*\"};minor=$${minor%%\"*};echo $$minor)

AR = m68k-amigaos-ar
AS = m68k-amigaos-as
CC = m68k-amigaos-gcc

ASFLAGS  = -I include
CFLAGS   = -I include -fno-builtin
C++FLAGS = -fno-exceptions -fno-rtti
LDFLAGS  = -noixemul -L $(OUTDIR)
#LDFLAGS += -Wl,-M
LIBS     = -lcryptossh

ifneq ($(Profile),)
OUTDIR := Profile
CFLAGS += -Os -mregparm=3 -pg -DPROFILE
LIB_EXT = a
else
ifneq ($(Release),)
OUTDIR := Release
CFLAGS += -O2 -fomit-frame-pointer -mregparm=3
#-fno-tree-loop-im -fno-move-loop-invariants
LDFLAGS += $(STRIP)
LDFLAGS += -fbaserel
ifeq ($(STRIP),)
LDFLAGS += -Wl,-u___checkstack 
endif
LIB_EXT = library
else
OUTDIR := Debug
LDFLAGS += -g -mregparm=3
CFLAGS += -O2 -fno-tree-loop-im
LIB_EXT = a
endif
endif 


CFLAGS +=$(CPU)

ifeq ($(linux),)
ifeq ($(CPU),-m68020)
EXTRA_LIB_SOURCES += fastmath-mul32.asm edmul32.asm edmul121665-32.asm edsquare32.asm fastmath-all.asm poly.asm
else
EXTRA_LIB_SOURCES += fastmath-mul16.asm edmul16.asm edmul121665-16.asm edsquare16.asm fastmath-all.asm poly16.asm
endif
endif


TARGETS   = bebbossh bebbosshd bebbosshkeygen bebboscp
TPROGRAMS = $(patsubst %,$(OUTDIR)/%,$(TARGETS))
 
ASMSOURCES = $(wildcard src/*.asm)
ASMOBJECTS = $(patsubst src/%.asm,$(OUTDIR)/%.o,$(ASMSOURCES))
 
LIB_SOURCES = bc.cpp aes.cpp chacha20.cpp poly1305.cpp chacha20poly1305ssh.cpp \
			dump.c gcm.cpp log.c md.cpp sha256.cpp sha512.cpp sha384512.cpp \
			ssh.cpp loaded25519key.cpp splitline.cpp \
			mimedecode.c mimeencode.c rand.c equals.cpp unhexlify.c \
			x25519.c ed25519.c ed25519s.c ed25519v.c c++support-lib.cpp \
			$(EXTRA_LIB_SOURCES)
LIB_OBJECTS = $(patsubst %.asm,$(OUTDIR)/%.o, $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(LIB_SOURCES))))

SSH_SOURCES = bebbossh.cpp keyboard.cpp c++support.cpp client.cpp clientchannel.cpp stack.cpp
SSH_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(SSH_SOURCES)))

SCP_SOURCES = bebboscp.cpp keyboard.cpp c++support.cpp client.cpp clientchannel.cpp stack.cpp
SCP_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(SCP_SOURCES)))

SSHD_SOURCES = bebbosshd.cpp sshsession.cpp forwardchannel.cpp sftpchannel.cpp shellchannel.cpp channel.cpp stack.cpp c++support.cpp
SSHD_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(SSHD_SOURCES)))

C++SOURCES = $(wildcard src/*.cpp)
C++OBJECTS = $(patsubst src/%.cpp,$(OUTDIR)/%.o,$(C++SOURCES))
TOBJECTS   = $(filter $(OUTDIR)/test%,$(C++OBJECTS)) 
TESTS      = $(patsubst %.o,%,$(TOBJECTS))

HEADERS = $(shell find 2>/dev/null include -type f)

all: pre
	mkdir -p $(OUTDIR)
	echo $(TESTS) $(TPROGRAMS)
	$(MAKE) $(TESTS) $(TPROGRAMS)

pre: 
	echo $(LIB_OBJECTS)
	mkdir -p $(OUTDIR)

ifeq ($(LIB_EXT),a) 
$(OUTDIR)/libcryptossh.a: $(LIB_OBJECTS)
	rm -rf $@
	m68k-amigaos-ar rcs $@ $(LIB_OBJECTS)
else
$(OUTDIR)/libcryptossh.a: $(LIB_OBJECTS) src/libcryptossh.def
	cd $(OUTDIR); \
	CFLAGS=$(CPU) LIB_MODE=-fbaserel mkstub libcryptossh ../src/libcryptossh.def

$(OUTDIR)/libcryptossh.library: $(OUTDIR)/libcryptossh.a 
	m68k-amigaos-gcc ${CPU} -shared -noixemul $(LIB_OBJECTS) $(OUTDIR)/libcryptossh-support/export*.o -o $@ \
	-Wl,-ulibVersionMajor=$(MAJOR),-ulibVersionMinor=$(MINOR),-ulibName=libcryptossh \
	$(STRIP)
endif

$(OUTDIR)/bebbossh: $(SSH_OBJECTS) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $(filter-out %.$(LIB_EXT),$^) $(LIBS) -o $@

$(OUTDIR)/bebboscp: $(SCP_OBJECTS) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $(filter-out %.$(LIB_EXT),$^) $(LIBS) -o $@

$(OUTDIR)/bebbosshd: $(SSHD_OBJECTS) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $(filter-out %.$(LIB_EXT),$^) $(LIBS) -o $@

$(OUTDIR)/bebbosshkeygen: $(OUTDIR)/bebbosshkeygen.o $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $< $(LIBS) -o $@

$(TESTS): $(TOBJECTS) Makefile $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $(patsubst $(OUTDIR)/%,src/%.cpp,$@)  $(OUTDIR)/c++support-lib.o $(LIBS) -o $@
	cd $(OUTDIR); vamos -C20 -v -- $(patsubst $(OUTDIR)/%,%,$@)

$(OUTDIR)/%.o: src/%.cpp Makefile $(HEADERS)
#	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -S
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@
 
$(OUTDIR)/%.o: src/%.c Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $< -o $@

ifeq ($(linux),)
$(OUTDIR)/%.o: src/%.asm Makefile $(HEADERS)
	$(AS) $(CPU) $(ASFLAGS) $< -o $@

$(OUTDIR)/aes.o: src/aes.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O2

$(OUTDIR)/gcm.o: src/gcm.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O2

$(OUTDIR)/fastmath.o: src/fastmath.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O2		
endif


clean:
	rm -rf $(OUTDIR)/*

	
ifneq ($(Release),)
install: all $(OUTDIR)/bebbossh $(OUTDIR)/bebbosshd $(OUTDIR)/bebbosshkeygen $(OUTDIR)/bebboscp $(OUTDIR)/libcryptossh.library
	cp $(OUTDIR)/bebbossh $(DEST)
	cp $(OUTDIR)/bebbosshd $(DEST)
	cp $(OUTDIR)/bebbosshkeygen $(DEST)
	cp $(OUTDIR)/bebboscp $(DEST)
	cp $(OUTDIR)/libcryptossh.library $(DEST)
else
install: all $(OUTDIR)/bebbossh $(OUTDIR)/bebbosshd $(OUTDIR)/bebbosshkeygen $(OUTDIR)/bebboscp 
	cp $(OUTDIR)/bebbossh $(DEST)
	cp $(OUTDIR)/bebbosshd $(DEST)
	cp $(OUTDIR)/bebbosshkeygen $(DEST)
	cp $(OUTDIR)/bebboscp $(DEST)
endif
