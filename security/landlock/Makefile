ccflags-$(CONFIG_SECURITY_LANDLOCK) += -Werror=unused-function

obj-$(CONFIG_SECURITY_LANDLOCK) := landlock.o

landlock-y := init.o providers.o common.o hooks.o hooks_cred.o hooks_ptrace.o hooks_fs.o
