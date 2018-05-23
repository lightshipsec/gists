/**
 * Copyright Lightship Security, Inc. 2017
 * info@lightshipsec.com
 *
 * Proof of concept SystemTap/jprobes to tap directly into raw
 * entropy samples in live Linux kernel. Some cleverness added
 * to try to attribute samples correctly.
 * ------------------------------------------------------------------
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


/**
 * How it works
 * ============
 * We use the jprobes API to easily tap functions. jprobes provides a much
 * easier way to capture the tapped function's arguments than with kprobes.
 * However, jprobes may be deprecated (or soon be) in very modern kernels.
 *
 * Basically, we analyzed the call flow of the ${KSRC}/drivers/char/random.c
 * file for our kernel in question and understand the entropy points of 
 * interest.  These are basically things like add_timer_randomess, 
 * add_disk_randomness, add_input_randomness, add_interrupt_randomness, etc.  
 * There are others and they depend on the given kernel.
 *
 * In the 3.19 kernel (which this proof of concept was based on), the 
 * add_input_randomness and add_disk_randomness really just are wrapper calls 
 * to add_timer_randomness.  add_interrupt_randomess is its own thing.
 *
 * But at the end of the day, all of these entropy sample calls get mixed into
 * the primary entropy pool via calls to _mix_pool_bytes depending on who the 
 * parent calling function is.  So instead of tapping on all of the various 
 * functions, we tap on _mix_pool_bytes only and then try to attribute the 
 * caller based on the available call frame. Not all code paths leading to 
 * _mix_pool_bytes are a result of entropy-adding calls, so we need to be 
 * careful to only report on entropy-significant calls.
 *
 * Other ways in which this can be done is to tap on all kernel functions of
 * interest but realize that not all calls to, say, add_input_randomness() will
 * yield an associated add_timer_randomness() (due to how the kernel prevents
 * repeated calls with the same underlying input value -- such as holding down
 * the ENTER key).
 *
 * Additionally, kprobes could be used to jump into the middle of a function 
 * call such as add_interrupt_randomness() (as long as it was not inlined) to 
 * capture the data before it is XOR'd and mixed.  However, such operations 
 * are constant and do not lose entropy, therefore it isn't of much value to 
 * try to capture the unmixed interrupt register data.
 *
 * With the function properly attributed, we can then intelligently spit out 
 * the caller and the entropy sample via the kernel logging mechanism.  Since 
 * kernel logs tend to be redirected to syslog which will send to 
 * /var/log/syslog or /var/log/messages or similar, be careful not to bias the 
 * collection with spurious add_disk_randomness events that are caused by the 
 * emitting of entropy samples to the log file.  Instead, write to a memory 
 * mapped file (or similar construct).
 *
 * The concern with measuring entropy is that we never want to alter the 
 * entropy collecting mechanism.  Since tapping the kernel basically introduces
 * overhead via an additional call path with some potentially expensive 
 * function calls (eg. snprintf) we are going to effectively slow down some of 
 * the calls.  Since the primary entropy data feed for x86 processors is the 
 * high precision timer, we're essentially altering specific values due to 
 * slowdown.  However, we are not changing the *distribution* of entropy or 
 * it's specific qualities.  Our changes should realistically introduce 
 * homogenous changes rather than biased changes. Therefore, this kind of 
 * intrusive tapping should not adversely affect the overall entropy analysis.
 *
 * SystemTap/kprobes/jprobes requires compiled support for SystemTap which may
 * or may not be the case in a custom compiled kernel.  (And honestly, if you 
 * are compiling your own kernels, then perhaps altering 
 * ${KSRC}/drivers/char/random.c to capture the raw samples is a better way to
 *  do this.)  It also requires support of kallsyms in order to perform name 
 * lookups.  If kallsyms is not available, then this can still work, but you 
 * need the kernel address for the _mix_pool_bytes function instead of letting 
 * the jprobes/kprobes API do the translation from string to address for you.
 *
 *
 * Compile with a GNU Makefile (or sequence) like this:
 *
 * # Pass CFLAGS from environment if necessary
 * obj-m += linux-eg-ext.o
 * ccflags-y += $(CFLAGS) -std=gnu99 -Wno-declaration-after-statement -Wno-unused-variable -O2 #-fno-inline -g
 *
 * all:
 *      make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
 * clean:
 *      make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
 *
 *
 * Install in a running Linux kernel: sudo insmod linux-eg-ext.ko
 *
 * Check the output in /var/log/messages (or wherever kernel events are sent 
 * in your system).
 *
 * Remove from the running kernel (note underscores instead of hyphens): 
 *     sudo rmmod linux_eg_ext
 *
 */

/* At the top of the file, before any includes */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/string.h>


/**
 * Semi-optimized sample output routine.
 *
 * Prints from least significant byte to most significant byte. 
 * Individual bytes are properly ordered.
 * eg. LSB to MSB: 000102030405060708090a0b0c0d0e0f
 * MSB to LSB:     0f0e0d0c0b0a09080706050403020100
 *
 * To gain insight into how fast it is, compile with CFLAGS=-DPERFCHECK.
 * The log will emit values in nanoseconds(!).
 * To understand the performance baseline without any printing or
 * symbol resolution, compile with CFLAGS=-DPERFCHECK -DNOPRINTSAMPLE which
 * will prevent printing the entropy sample though still performs
 * symbol resolution tasks.  Compiling with -DNOPRINT will prevent symbol 
 * resolution lookup, which in turn prevents printing of the sample as well.
 *
 * Note that this function will allocate space on the stack. If the
 * sample is really large, then you might get wierd stack faults.
 * If this is the case, then you will need to chunk the sample into
 * pieces and call the printer repeatedly.
 */
unsigned char f_dec2hex[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

static inline int print_entropy_sample( const char *fn, const void *sample, unsigned int len )  {
#ifdef PERFCHECK
    __u64 sj = get_cycles();
#endif

#ifndef NOPRINTSAMPLE
    /* Create an entropy string to print out */
    unsigned char buf[len*2+1], *p = &buf[0];
    unsigned char *b = (unsigned char *)(sample);
    for( int i = 0; i < len; i ++)  {
        register unsigned char c = (unsigned char)(*(b+i));
        *(p++) = f_dec2hex[c >> 4];
        *(p++) = f_dec2hex[c & 0x0F];
    }
    *p = '\x0';
    pr_info( "%s sample (%u bytes): %s\n", fn, len, buf );
#endif  /* ifndef NOPRINTSAMPLE */

#ifdef PERFCHECK
    __u64 ej = get_cycles();
    pr_info( "Time for print_entropy_sample to execute: %llu\n", sj < ej ? (ej - sj) : (0xFFFFFFFFFFFFFFFF - sj + ej) );
#endif
    return 0;
} 


/**
 * This function tries to be fast and clever.
 * In order to properly attribute the entropy sample to either a disk event,
 * input event, interrupt event, etc., we need to know who called it.
 * We use the compiler to provide us with the call history and we then 
 * switch on the name of the function to properly know the attribution.
 * This is dependent on the kernel and what functions are applied.
 * You can do this more slowly but more explicitly.
 * Note that it doesn't take into account any functions such as 
 * add_device_randomness, or other components of the entropy noise which aren't 
 * necessarily credited with entropy, but are still possibly of interest. These 
 * would need to be added.
 *
 * The call tree is basically distilled down as the number of call frames away 
 * from the mix_pool_bytes function.  THIS IS KERNEL SPECIFIC.
 *
 * add_device_randomness calls _mix_pool_bytes (1 step away)
 *      But this call doesn't add entropy, so we can safely ignore it
 * add_timer_randomness calls mix_pool_bytes which calls _mix_pool_bytes
 *      (2 steps away)
 *      Depending on the kernel version, this function doesn't add randomness 
 *      on its own; it is called by something else more interesting.
 * add_input_randomness calls add_timer_randomness (3 steps away)
 * add_interrupt_randomness calls __mix_pool_bytes which calls _mix_pool_bytes
 *      (2 steps away)
 * add_disk_randomness calls add_timer_randomness (3 steps away)
 * add_hwgenerator_randomness calls mix_pool_bytes (2 steps away)
 *
 * So if I get my direct parent caller, then it will be (1):
 *      add_device_randomness
 *      mix_pool_bytes
 *      __mix_pool_bytes
 *
 * From (1), if the parent is mix_pool_bytes, then it's parent can be one of:
 *      write_pool
 *      add_timer_randomness
 *      add_hwgenerator_randomness
 *
 * From (1), if the parent is __mix_pool_bytes, then it's parent can be one of:
 *      add_interrupt_randomness
 *      extract_buf (which is not an entropy adder and we need to ignore it)
 *
 *  If you get write_pool's parent, then it will be:
 *      random_ioctl
 *      random_write (which is not an entropy adder and we need to ignore it)
 *
 *  If you get add_timer_randomness's parent, then it will be:
 *      add_input_randomness
 *      add_disk_randomness
 */
static inline void k_mix_pool_bytes(void *r, const void *in, int nbytes)  {
#ifdef PERFCHECK
    __u64 sj = get_cycles(), ej = 0LL;
#endif

#ifndef NOPRINT
    char func_name[256];
    snprintf(func_name, sizeof(func_name)-1, "%pf", __builtin_return_address( 0 ) );

    /* After we resolve the parent, there is only one potential function call that starts with an underscore
     * and that will lead to "add_interrupt_randomness", so we can bypass making a second call and handle
     * the interrupt randomness earlier.
     */ 
    switch( func_name[0] )  {
        case '_':
            /* The caller might be extract_buf, which we need to ignore */
            snprintf(func_name, sizeof(func_name)-1, "%pf", __builtin_return_address( 1 ) );
            if (func_name[0] == 'e') goto fend;

            /* Otherwise, it must be add_interrupt_entropy */
            print_entropy_sample( func_name, in, nbytes );
            goto fend;
        case 'm':
            snprintf(func_name, sizeof(func_name)-1, "%pf", __builtin_return_address( 1 ) );
#ifdef PRINTIOCTL
            switch ( func_name[0] ) {
                case 'w':       /* write_pool */
                    snprintf(func_name, sizeof(func_name)-1, "%pf", __builtin_return_address( 2 ) );
                    if ( func_name[0] == 'r' && func_name[7] == 'i' ) { /* random_ioctl */
                        print_entropy_sample( func_name, in, nbytes );
                        goto fend;
                    }
            }
#endif
            /* Differentiator at this level is in the 5th byte */
            switch( func_name[4] )  {
                case 't':       /* add_timer_randomness */
                    snprintf(func_name, sizeof(func_name)-1, "%pf", __builtin_return_address( 2 ) );
                    print_entropy_sample( func_name, in, nbytes );
                    goto fend;
                case 'h':       /* add_hwgenerator_randomness */
                    print_entropy_sample( "get_hwgenerator_randomness", in, nbytes );
                    goto fend;
                default:
                    goto fend;
            }
            goto fend;

        default: goto fend;
    }


#if 0
    /* Here's the slow and explicit way of doing it. Left here as a reference. */
    if( strncmp( func_name, "__mix_pool_bytes", 7 ) == 0 ) 
        snprintf(func_name, sizeof(func_name)-1, "%pf", __builtin_return_address( 1 ) );
    else if( strncmp( func_name, "mix_pool_bytes", 7 ) == 0 ) 
        snprintf(func_name, sizeof(func_name)-1, "%pf", __builtin_return_address( 1 ) );

    if( strncmp( func_name, "add_timer_randomness", 7 ) == 0 ) 
        snprintf(func_name, sizeof(func_name)-1, "%pf", __builtin_return_address( 2 ) );

    if( strncmp( func_name, "add_input_randomness", 7 ) == 0 )
        print_entropy_sample( func_name, in, nbytes );
    else if( strncmp( func_name, "add_disk_randomness", 7 ) == 0 )
        print_entropy_sample( func_name, in, nbytes );
    else if( strncmp( func_name, "add_interrupt_randomness", 7 ) == 0 )
        print_entropy_sample( func_name, in, nbytes );
    else if( strncmp( func_name, "add_hwgenerator_randomness", 7 ) == 0 )
        print_entropy_sample( func_name, in, nbytes );
#endif
 
fend:
#endif  /* ifndef NOPRINT */

#ifdef PERFCHECK
    ej = get_cycles();
    pr_info( "Time for k_mix_pool_bytes to execute: %llu\n", sj < ej ? (ej - sj) : (0xFFFFFFFFFFFFFFFF - sj + ej) );
#endif

    jprobe_return();
}



#define MAX_JPROBES 1
/* Probes structure */
static struct jprobe my_jprobes[MAX_JPROBES] = {
    {
        .kp.symbol_name = "_mix_pool_bytes",
        .entry = (kprobe_opcode_t *)k_mix_pool_bytes,
    },
};


static int __init my_module_init(void){
    int ret = 0;    /* Assume all okay */
    pr_info( "Initializing the kernel module\n" );

    for( int i = 0; i < MAX_JPROBES; i ++)  {
        ret = register_jprobe(&(my_jprobes[i]));
        if( ret < 0 )  {
            pr_err( "register_jprobe failed, returned %d\n", ret );
            goto __init_failure;
        }
        pr_info( "Planted jprobe for function %s at %p, handler addr %p\n", my_jprobes[i].kp.symbol_name, my_jprobes[i].kp.addr, my_jprobes[i].entry );
    }

    pr_info( "Module setup complete.\n" );
    goto __init_success;


__init_failure:
    pr_info( "Error setting up module. Tearing down.\n" );

    for( int i = 0; i < MAX_JPROBES; i ++)
        unregister_jprobe(&(my_jprobes[i]));

__init_success:
    return ret;
}

/* Module teardown. */
static void __exit my_module_exit(void){
    for( int i = 0; i < MAX_JPROBES; i ++)
        unregister_jprobe(&(my_jprobes[i]));
    pr_info( "Module teardown complete\n" );
}


module_init(my_module_init);
module_exit(my_module_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lightship Security, Inc.");
MODULE_DESCRIPTION("Gathers raw and unconditioned entropy from Linux entropy noise sources.");
MODULE_VERSION("1.0");
