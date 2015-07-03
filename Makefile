#
# $FreeBSD$
#

PROG=	bhyve

DEBUG_FLAGS= -g -O0

MAN=	bhyve.8

SRCS=	\
	atkbdc.c		\
	acpi.c			\
	bhyverun.c		\
	block_if.c		\
	consport.c		\
	dbgport.c		\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	net_backends.c		\
	pci_ahci.c		\
	pci_emul.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_passthru.c		\
	pci_ptnetmap_memdev.c	\
	pci_virtio_block.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_uart.c		\
	pm.c			\
	post.c			\
	rtc.c			\
	smbiostbl.c		\
	task_switch.c		\
	uart_emul.c		\
	virtio.c		\
	xmsr.c			\
	spinup_ap.c

.PATH:	${.CURDIR}/../../sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

.ifdef CROSS_BUILD
BASEDIR=/home/stefano/repos
S=${BASEDIR}/freebsd
M=${BASEDIR}/obj_head${S}/tmp/usr
.PATH: ${S}/sys/amd64/vmm
CFLAGS = -I${M}/include -I/${S}/sys -L${M}/lib
.endif

DPADD=	${LIBVMMAPI} ${LIBMD} ${LIBUTIL} ${LIBPTHREAD}
LDADD=	-lvmmapi -lmd -lutil -lpthread

WARNS?=	1

.include <bsd.prog.mk>
