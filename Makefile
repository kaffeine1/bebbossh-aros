.PHONY: all pre install

MAJOR ?= $(shell major=$$(grep MAJOR include/revision.h);major=$${major#*\"};major=$${major%%\"*};echo $$major)
MINOR ?= $(shell minor=$$(grep MINOR include/revision.h);minor=$${minor#*\"};minor=$${minor%%\"*};echo $$minor)

ifdef linux
AR = ar
CC = gcc
CFLAGS   = -I include -Os -fPIE -flto
C++FLAGS = -fno-exceptions -fno-rtti
OUTDIR ?= linux
LIB_EXT = a
LDFLAGS = -L linux -pie $(STRIP)
LIBS     = -lcryptossh 
LIBS_D   = -lpam -lpam_misc
#LIBS = -static

else
AR = m68k-amigaos-ar
AS = m68k-amigaos-as
CC = m68k-amigaos-gcc

ASFLAGS  = -I include
CFLAGS   = -I include -fno-builtin
C++FLAGS = -fno-exceptions -fno-rtti
LDFLAGS  = -noixemul -L $(OUTDIR) 
#-Wl,--gc-sections
#LDFLAGS += -Wl,-M
LIBS     = -lcryptossh

ifdef Profile
OUTDIR := Profile
CFLAGS += -Os -mregparm=3 -pg -DPROFILE
LIB_EXT = a
else
ifdef Release
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

ifeq ($(CPU),-m68020)
EXTRA_LIB_SOURCES += fastmath-mul32.asm edmul32.asm edmul121665-32.asm edsquare32.asm fastmath-all.asm poly.asm
else
EXTRA_LIB_SOURCES += fastmath-mul16.asm edmul16.asm edmul121665-16.asm edsquare16.asm fastmath-all.asm poly16.asm
endif
endif


TARGETS   = bebbossh bebboscp bebbosshkeygen bebbosshd
TPROGRAMS = $(patsubst %,$(OUTDIR)/%,$(TARGETS))
 
ASMSOURCES = $(wildcard $(srcdir)/*.asm)
ASMOBJECTS = $(patsubst $(srcdir)/%.asm,$(OUTDIR)/%.o,$(ASMSOURCES))
 
LIB_SOURCES = bc.cpp aes.cpp chacha20.cpp poly1305.cpp chacha20poly1305ssh.cpp \
			dump.c gcm.cpp log.c md.cpp sha256.cpp sha512.cpp sha384512.cpp \
			ssh.cpp loaded25519key.cpp splitline.cpp fastmath.cpp vector.cpp \
			mimedecode.c mimeencode.c rand.c equals.cpp unhexlify.c \
			x25519.cpp ed25519.cpp ed25519s.cpp ed25519v.cpp c++support-lib.cpp home.cpp\
			$(EXTRA_LIB_SOURCES)
LIB_OBJECTS = $(patsubst %.asm,$(OUTDIR)/%.o, $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(LIB_SOURCES))))

SSH_SOURCES = bebbossh.cpp console.cpp keyboard.cpp c++support.cpp client.cpp clientchannel.cpp stack.cpp home.cpp
SSH_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(SSH_SOURCES)))

SCP_SOURCES = bebboscp.cpp console.cpp keyboard.cpp c++support.cpp client.cpp clientchannel.cpp stack.cpp home.cpp
SCP_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(SCP_SOURCES)))

SSHD_SOURCES = bebbosshd.cpp sshsession.cpp forwardchannel.cpp sftpchannel.cpp shellchannel.cpp channel.cpp stack.cpp c++support.cpp home.cpp
SSHD_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(SSHD_SOURCES)))

srcdir := src

C++SOURCES = $(wildcard $(srcdir)/*.cpp)
C++OBJECTS = $(patsubst $(srcdir)/%.cpp,$(OUTDIR)/%.o,$(C++SOURCES))
TOBJECTS   = $(filter $(OUTDIR)/test%,$(C++OBJECTS)) 
TESTS      = $(patsubst %.o,%,$(TOBJECTS))

HEADERS = $(shell find 2>/dev/null include -type f)

# prepend $(srcdir)/ to each source filename
SSH_SRCS_FULL := $(patsubst %,$(srcdir)/%,$(SSH_SOURCES))
SCP_SRCS_FULL := $(patsubst %,$(srcdir)/%,$(SCP_SOURCES))
SSHD_SRCS_FULL := $(patsubst %,$(srcdir)/%,$(SSHD_SOURCES))

all: pre
	mkdir -p $(OUTDIR)
	echo $(TESTS) $(TPROGRAMS)
	$(MAKE) $(TESTS) $(TPROGRAMS)

pre: 
	echo $(LIB_OBJECTS)
	mkdir -p $(OUTDIR)
	echo $(SSH_SRCS_FULL)

ifeq ($(LIB_EXT),a) 
$(OUTDIR)/libcryptossh.a: $(LIB_OBJECTS)
	rm -rf $@
	$(AR) rcs $@ $(LIB_OBJECTS)
else
$(OUTDIR)/libcryptossh.a: $(LIB_OBJECTS) $(srcdir)/libcryptossh.def
	cd $(OUTDIR); \
	CFLAGS=$(CPU) LIB_MODE=-fbaserel mkstub libcryptossh ../$(srcdir)/libcryptossh.def

$(OUTDIR)/libcryptossh.library: $(OUTDIR)/libcryptossh.a 
	m68k-amigaos-gcc ${CPU} -shared -noixemul $(LIB_OBJECTS) $(OUTDIR)/libcryptossh-support/export*.o -o $@ \
	-Wl,-ulibVersionMajor=$(MAJOR),-ulibVersionMinor=$(MINOR),-ulibName=libcryptossh \
	$(STRIP)
endif

# does not work yet...
ifdef Releasex
WHOLEPROG = -fwhole-program

$(OUTDIR)/bebbossh: $(SSH_SRCS_FULL) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	rm -f $(OUTDIR)/bebbossh_all.cpp
	cat $(SSH_SRCS_FULL) > $(OUTDIR)/bebbossh_all.cpp
	$(CC) $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $(WHOLEPROG) $(OUTDIR)/bebbossh_all.cpp $(LIBS) -o $@

$(OUTDIR)/bebboscp: $(SCP_SRCS_FULL) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	rm -f $(OUTDIR)/bebboscp_all.cpp
	cat $(SCP_SRCS_FULL) > $(OUTDIR)/bebboscp_all.cpp
	$(CC) $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $(WHOLEPROG) $(OUTDIR)/bebboscp_all.cpp $(LIBS) -o $@

$(OUTDIR)/bebbosshd: $(SSHD_SRCS_FULL) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	rm -f $(OUTDIR)/bebbosshd_all.cpp
	cat $(SSHD_SRCS_FULL) > $(OUTDIR)/bebbosshd_all.cpp
	$(CC) $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $(WHOLEPROG) $(OUTDIR)/bebbosshd_all.cpp $(LIBS) -o $@

$(OUTDIR)/bebbosshkeygen: $(srcdir)/bebbosshkeygen.cpp $(OUTDIR)/libcryptossh.$(LIB_EXT)
	rm -f $(OUTDIR)/bebbosshkeygen_all.cpp
	cat $(srcdir)/bebbosshkeygen.cpp $(srcdir)/home.cpp > $(OUTDIR)/bebbosshkeygen_all.cpp
	$(CC) $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $(WHOLEPROG) $(OUTDIR)/bebbosshkeygen_all.cpp $(LIBS) -o $@

else

$(OUTDIR)/bebbossh: $(SSH_OBJECTS) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $(filter-out %.$(LIB_EXT),$^) $(LIBS) -o $@

$(OUTDIR)/bebboscp: $(SCP_OBJECTS) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $(filter-out %.$(LIB_EXT),$^) $(LIBS) -o $@

$(OUTDIR)/bebbosshd: $(SSHD_OBJECTS) $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $(filter-out %.$(LIB_EXT),$^) $(LIBS) $(LIBS_D) -o $@

$(OUTDIR)/bebbosshkeygen: $(OUTDIR)/bebbosshkeygen.o $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $< $(OUTDIR)/home.o $(LIBS) -o $@

endif

$(TESTS): $(TOBJECTS) Makefile $(OUTDIR)/libcryptossh.$(LIB_EXT)
	$(CC) $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $(patsubst $(OUTDIR)/%,$(srcdir)/%.cpp,$@)  $(OUTDIR)/c++support-lib.o $(LIBS) -o $@
ifeq ($(linux),)	
	cd $(OUTDIR); vamos -C20 -v -- $(patsubst $(OUTDIR)/%,%,$@)
else
	-cd $(OUTDIR); ./$(patsubst $(OUTDIR)/%,%,$@)
endif

$(OUTDIR)/%.o: $(srcdir)/%.cpp Makefile $(HEADERS)
#	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -S
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@
 
$(OUTDIR)/%.o: $(srcdir)/%.c Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $< -o $@

ifeq ($(linux),)
$(OUTDIR)/%.o: $(srcdir)/%.asm Makefile $(HEADERS)
	$(AS) $(CPU) $(ASFLAGS) $< -o $@

$(OUTDIR)/aes.o: $(srcdir)/aes.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O2

$(OUTDIR)/gcm.o: $(srcdir)/gcm.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O2

$(OUTDIR)/fastmath.o: $(srcdir)/fastmath.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O2		
endif

clean:
	rm -rf $(OUTDIR)/*

ifdef linux
.PHONY: install
install: all
else
ifdef Release
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
endif
