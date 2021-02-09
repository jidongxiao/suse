cmd_/home/mzq/Desktop/invd/aes.o := gcc -Wp,-MD,/home/mzq/Desktop/invd/.aes.o.d  -nostdinc -isystem /usr/lib/gcc/i686-linux-gnu/4.6/include -I/usr/src/linux-3.12.6/arch/x86/include -Iarch/x86/include/generated  -Iinclude -I/usr/src/linux-3.12.6/arch/x86/include/uapi -Iarch/x86/include/generated/uapi -I/usr/src/linux-3.12.6/include/uapi -Iinclude/generated/uapi -include /usr/src/linux-3.12.6/include/linux/kconfig.h -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -O2 -m32 -msoft-float -mregparm=3 -freg-struct-return -mno-mmx -mno-sse -fno-pic -mpreferred-stack-boundary=2 -march=i586 -mtune=generic -maccumulate-outgoing-args -Wa,-mtune=generic32 -ffreestanding -fstack-protector -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -Wframe-larger-than=1024 -Wno-unused-but-set-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -g -pg -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -DCC_HAVE_ASM_GOTO  -DMODULE  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(aes)"  -D"KBUILD_MODNAME=KBUILD_STR(isoToken)" -c -o /home/mzq/Desktop/invd/.tmp_aes.o /home/mzq/Desktop/invd/aes.c

source_/home/mzq/Desktop/invd/aes.o := /home/mzq/Desktop/invd/aes.c

deps_/home/mzq/Desktop/invd/aes.o := \
  /home/mzq/Desktop/invd/config.h \
    $(wildcard include/config/h.h) \
  /home/mzq/Desktop/invd/aes.h \
  include/linux/string.h \
    $(wildcard include/config/binary/printf.h) \
  include/linux/compiler.h \
    $(wildcard include/config/sparse/rcu/pointer.h) \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
    $(wildcard include/config/kprobes.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
    $(wildcard include/config/arch/use/builtin/bswap.h) \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  include/uapi/linux/types.h \
  /usr/src/linux-3.12.6/arch/x86/include/uapi/asm/types.h \
  /usr/src/linux-3.12.6/include/uapi/asm-generic/types.h \
  include/asm-generic/int-ll64.h \
  include/uapi/asm-generic/int-ll64.h \
  /usr/src/linux-3.12.6/arch/x86/include/uapi/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/uapi/asm-generic/bitsperlong.h \
  /usr/src/linux-3.12.6/include/uapi/linux/posix_types.h \
  include/linux/stddef.h \
  include/uapi/linux/stddef.h \
  /usr/src/linux-3.12.6/arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  /usr/src/linux-3.12.6/arch/x86/include/uapi/asm/posix_types_32.h \
  /usr/src/linux-3.12.6/include/uapi/asm-generic/posix_types.h \
  /usr/lib/gcc/i686-linux-gnu/4.6/include/stdarg.h \
  include/uapi/linux/string.h \
  /usr/src/linux-3.12.6/arch/x86/include/asm/string.h \
  /usr/src/linux-3.12.6/arch/x86/include/asm/string_32.h \
    $(wildcard include/config/x86/use/3dnow.h) \
    $(wildcard include/config/kmemcheck.h) \

/home/mzq/Desktop/invd/aes.o: $(deps_/home/mzq/Desktop/invd/aes.o)

$(deps_/home/mzq/Desktop/invd/aes.o):
