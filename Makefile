#
#
#
RM			= rm -f 
OBJ			= .o 
SHEXT		= .so
SHINIT		= __library_attach
SHFINI		= __library_detach
KRB5INC		=
KRB5LIB		= -lgssapi_krb5
XLIB		= lib
XNAME		= qossnc_krb5
SRCS 		= qossnc_core.c qossnc_gss.c qossnc_krb5.c
OBJS		= $(patsubst %.c,%.o,$(SRCS))
TARGET		= $(XLIB)$(XNAME)$(SHEXT)

CC			= gcc 
CFLAGS		= -Wall -ansi -fPIC -DQOSSNC_UNIX
LIBS		= -ldl $(KRB5LIB) 
LD			= gcc 
LDFLAGS		= -shared

ifeq ($(DEBUG),1)
	CFLAGS += -g -O0
else
	CFLAGS += -O2
endif

ifneq ($(KRB5INC),)
	CFLAGS += -I$(KRB5INC)
endif

ifdef SHINIT
	LDFLAGS += -Wl,-init,$(SHINIT)
endif

ifdef SHFINI
	LDFLAGS += -Wl,-fini,$(SHFINI)
endif

### targets
all:
	$(MAKE) do-all

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	$(MAKE) do-clean

do-all:	$(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -Wl,-soname,$@.1 -o $@.1.0 $(OBJS) $(LIBS)
	ln -sf $@.1.0 $@.1

do-clean:
	$(RM) core
	$(RM) *$(OBJ)
	$(RM) $(TARGET)*

### dependencies
qossnc_core.c: qossnc_gss.c qossnc_krb5.c

qossnc_gss.c: qossnc_gss.h

qossnc_krb5.c: qossnc_krb5.h
