default: build/fwb build/fwbcreate

CFLAGS+=-Iinclude -Og -g
CXXFLAGS+=$(CFLAGS)

OBJDIR=build
VPATH=src
include mk/noimplicit.mk
include mk/c_c++rules.mk

FWBOBJS=$(addprefix $(OBJDIR)/, \
	fwb.o \
  fwbcrypto.o \
)
FWBDEPS:=$(FWBOBJS:.o=.d)
sinclude $(FWBDEPS)

$(OBJDIR)/fwb: LDFLAGS+= -lcrypto
$(OBJDIR)/fwb: $(FWBOBJS)
	$(SHOW.ld)
	$Q$(CXX) $^ $(LDFLAGS) -o $@


FWBCREATEOBJS=$(addprefix $(OBJDIR)/, \
  fwbcreate.o \
	fwbcrypto.o \
)
FWBCREATEDEPS:=$(FWBCREATEOBJS:.o=.d)
sinclude $(FWBCREATEDEPS)

$(OBJDIR)/fwbcreate: LDFLAGS+= -lcrypto
$(OBJDIR)/fwbcreate: $(FWBCREATEOBJS)
	$(SHOW.ld)
	$Q$(CXX) $^ $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf "$(OBJDIR)"
