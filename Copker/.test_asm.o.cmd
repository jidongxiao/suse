cmd_/home/mzq/Desktop/invd/test_asm.o := gcc -Wp,-MD,/home/mzq/Desktop/invd/.test_asm.o.d  -nostdinc -isystem /usr/lib/gcc/i686-linux-gnu/4.6/include -I/usr/src/linux-3.12.6/arch/x86/include -Iarch/x86/include/generated  -Iinclude -I/usr/src/linux-3.12.6/arch/x86/include/uapi -Iarch/x86/include/generated/uapi -I/usr/src/linux-3.12.6/include/uapi -Iinclude/generated/uapi -include /usr/src/linux-3.12.6/include/linux/kconfig.h -D__KERNEL__  -D__ASSEMBLY__ -m32 -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1  -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1  -gdwarf-2        -DMODULE  -c -o /home/mzq/Desktop/invd/test_asm.o /home/mzq/Desktop/invd/test_asm.S

source_/home/mzq/Desktop/invd/test_asm.o := /home/mzq/Desktop/invd/test_asm.S

deps_/home/mzq/Desktop/invd/test_asm.o := \

/home/mzq/Desktop/invd/test_asm.o: $(deps_/home/mzq/Desktop/invd/test_asm.o)

$(deps_/home/mzq/Desktop/invd/test_asm.o):
