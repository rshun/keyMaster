include $(HOME)/etc/make.setup
USERINCL=
PUBOBJS = codeutil.o utility.o sha2.o
KEYOBJS = cJSON.o myKey.o
MYLIBSO = $(TOPLIBDIR)libmykey$(BITS).so
MYLIBA = $(TOPLIBDIR)libmykey$(BITS).a

all:.PHONY $(MYLIBA) myKey $(MYLIBSO) 

$(MYLIBA):$(PUBOBJS)
	$(LD) $@ $(PUBOBJS)

$(MYLIBSO):$(PUBOBJS)
	$(SO) $@ $(PUBOBJS)

myKey:$(KEYOBJS)
	$(EXE) $@ $(KEYOBJS) -L$(TOPLIBDIR) -lmykey$(BITS)

fpr:
	sourceanalyzer -b codescan -clean
	sourceanalyzer -b codescan make
	sourceanalyzer -b codescan -scan -f $(LIBNAME).fpr

.PHONY : clean
clean:
	$(RM) $(MYLIBA)
	$(RM) $(MYLIBSO)
	$(RM) $(PUBOBJS) $(KEYOBJS)
	$(RM) $(LIBNAME).fpr
