include ../etc/make.setup

ifeq ($(OSNAME),Linux)
	BINDIR=$(PROJECTHOME)/bin/
	OBJDIR=$(PROJECTHOME)/obj/
	LIBDIR=$(PROJECTHOME)/lib/
	INCDIR=$(PROJECTHOME)/util/
	LIBNAME=mykey$(BITS)
else ifeq ($(OSNAME),Windows)
	BINDIR:=$(PROJECTHOME)\\bin\\
	OBJDIR:=$(PROJECTHOME)\\obj\\
	LIBDIR:=$(PROJECTHOME)\\lib\\
	INCDIR=$(PROJECTHOME)\\util\\
	LIBNAME:=mykey$(BITS)
endif

SOURCE=$(wildcard *.c)
APPSOBJS = $(patsubst %.c,%.o,$(SOURCE))
APPS=$(APPSOBJS:%.o=%)

all: $(APPSOBJS) $(APPS)

%.o:%.c
	$(CC) $(EXECOMPILE) -fPIC -I $(INCDIR) -o $(OBJDIR)$*.o $*.c

%:%.o
	$(EXE) $@ $(OBJDIR)$@.o $(PARAM) 

install:
	$(MV) $(APPS) $(TOPBINDIR)

.PHONY : clean
clean:
ifeq ($(OSNAME),Windows)
	$(RM) $(addprefix $(OBJDIR),$(APPSOBJS)) $(APPS) 2>NUL
	$(RM) core.* *.exe 2>NUL
else
	$(RM) $(addprefix $(OBJDIR),$(APPSOBJS)) $(APPS)
	$(RM) core.* *.exe
endif
