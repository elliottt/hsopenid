GHC=ghc -odir $(ODIR) -hidir $(ODIR) -W
ODIR=.ghc
HSC2HS=hsc2hs
SRC=../src

all : $(ODIR) test

$(ODIR) :
	mkdir $(ODIR)

test : $(ODIR)/DH.hs test.hs
	$(GHC) -lcrypto -lssl --make test -i$(SRC) $(ODIR)/DH.hs -Wall

$(ODIR)/DH.hs : $(SRC)/Codec/Encryption/DH.hsc
	$(HSC2HS) $< -o $@

clean :
	$(RM) -r $(ODIR)
	$(RM) test

.PHONY : all clean depend
