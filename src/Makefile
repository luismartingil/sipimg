PJBASE=../lib/pjproject-1.10/
include $(PJBASE)/build.mak

# First go to PJBASE and do: ./configure;make;


CC      = $(PJ_CC)
LDFLAGS = $(PJ_LDFLAGS)
LDLIBS  = $(PJ_LDLIBS)
CFLAGS  = $(PJ_CFLAGS)
CPPFLAGS= ${CFLAGS}

NAME=img

all: $(NAME)

$(NAME): $(NAME).c
	$(CC) -static -o $@ $< $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)
#	$(CC) -o $@ $< $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(NAME).o $(NAME) *~