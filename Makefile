SRC    = airdecrypt.c
BIN    = airdecrypt
OBJDIR = build
BINDIR = bin

CC      = cc 
LIBS    = 
LDFLAGS = 
INCS    = 
CFLAGS  = 

OBJS       = $(SRC:%.c=$(OBJDIR)/%.o) 
BUILD_DIRS = $(sort $(OBJDIR) $(BINDIR) )

all: $(BIN)

$(BUILD_DIRS):
	mkdir -p $@

$(BIN): $(BUILD_DIRS) $(OBJS)
	$(CC) -o $(BINDIR)/$(BIN) $(OBJS) $(LIBS) $(LDFLAGS)

$(OBJDIR)/%.o : %.c
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

clean: 
	rm -rf $(OBJDIR) $(BINDIR)
