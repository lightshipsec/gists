/**
 * Originally authored by Greg McLearn at Lightship Security, Inc.
 *
 * Sample  NIST  SP800-90B (final)  mandatory  health tests.  The code is written
 * in such a way as to ensure that both health tests are running continuously and 
 * simultaneously.
 *
 * To the extent possible under law, the author(s)  have dedicated  all copyright 
 * and  related and  neighboring rights  to  this software  to the  public domain 
 * worldwide. This software is distributed without any warranty.
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software.  If not, see http://creativecommons.org/publicdomain/zero/1.0/.
 *
 * See legal wording at end of this file.
 *
 *
 *
 * Here is one way to test this on the command-line in  which  we introduce  a 
 * catastrophic RNG failure by biasing on bit pattern 00000000.
 * To make this fail faster, change divisor from 50 to something else, like 2
 * or convert to a relational check instead (eg. if b < 200).
 *
gcc -o NIST\ SP800-90B\ Health\ Tests NIST\ SP800-90B\ Health\ Tests.c -g
python - <<EOT | DEBUG=1 ./NIST\ SP800-90B\ Health\ Tests
import sys, random, time
random.seed(time.time())
while True:
   b=int(random.random()*256)
   if not b%50:
       sys.stdout.write(chr(0))
   else:
       sys.stdout.write(chr(b))
EOT
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


/**
 * These are the values that the implementor needs to determine.
 * H is determined by quantitative/statistical analysis of the entropy
 * samples. W is set based on whether the entropy samples are binary
 * (then W = 1024) or non-binary (then W = 512).  See section 4.4.2 in
 * NIST SP800-90B.
 */

/**
 * From entropy analysis, min-entropy 
 * (this is an example only and is not indicative of the 
 * entropy in general.
 */
#define _H  ((double)7.8)

/**
 * From review of entropy samples it is NOT binary data
 * (mainly because we are reading and understanding bytes)
 */
#define _W (512)

/**
 * Using Excel, calculate once and fix the value:
 * =1+CRITBINOM(W, power(2,(-H)),1-power(2,(-20))) 
 * as per footnote 10 in section 4.4.2 of NIST SP800-90B.
 */
#define AdPC (13)


typedef unsigned char Sample;

static int VERBOSE = 0;
static int DEBUG = 0;


unsigned char *toBinaryValue(Sample c)  {
    /* Convert char to binary representation */
    /* Not thread safe because it returns address of a static buffer. */
    static unsigned char buf[sizeof(c)*8+1];
    int i = 0; int j = 0;
    for (i = (sizeof(c)*8-1); i >= 0; i--, j++)
        snprintf(&buf[j], sizeof(buf)-1, "%u", (c >> i) & 1);
    buf[sizeof(c)*8] = 0;
    return &buf[0];
}


int getRawSample(FILE *noise, Sample *sample)  {
    /**
     * Get a single raw entropy noise sample. In our example, the sample is a 
     * byte.
     * Returns ENODATA if no data is available or 0 is data was read.
     * Data is returned back via the passed in sample pointer.
     */
    if(!sample) return ENODATA;
    if( fscanf(noise, "%c", sample) == EOF ) return ENODATA;
    VERBOSE && printf("Noise sample %s\n", toBinaryValue(*sample));
    return 0;
}

int samplesAreEqual(Sample sample1, Sample sample2)  {
    /**
     * Simply provide some way to compare for equality. In our example, we 
     * compare two bytes.  This function is present only to illustrate that
     * comparisons might actually be less than trivial.
     * Return 0 if not equal or non-zero if equal.
     */
    return sample1 == sample2;
}


/* I just don't want to have to link math library for the ceiling function
 * Note you can always dispense with math lib and CEIL macro and just precalc
 * but it would be less transparent in this gist.
 */
#define CEIL(x)     ( (x) < 0.0 ? (int)(x) : ( (float)((int)(x)) == (x) ? (int)(x) : (int)((x)+1.0) ) )

static Sample repetitionCountTestA = 0;
static unsigned int repetitionCountTestB = 1;
/* 20 comes from log_2(2^(-20)), as per SP 800-90B this is a reasonable 
 * choice for Type-I error detection in most applications.
 * It could be between 2^-20 and 2^-40.
 * An implementer might need to adjust depending on their risk
 * requirements, but it isn't something vendors are likely to want to play
 * too much with unless they understand the ramifications.
 */
static unsigned int repetitionCountTestC = (unsigned int)(1+CEIL(20 / _H));

int repetitionCountTest(unsigned char sample)  {
    /**
     * The repetition test is like an updated version of the stuck-bit test as 
     * per NIST SP800-90B.
     * Returns zero if everything went well, else returns non-zero if there is a health
     * test failure.
     */
    if (samplesAreEqual(sample, repetitionCountTestA))  {
        repetitionCountTestB += 1;
        DEBUG && printf("repetitionTest.B incremented to %u\n", repetitionCountTestB);
        if (repetitionCountTestB >= repetitionCountTestC)  {
            printf("Sample %s repeats with threshold %u\n", toBinaryValue(sample), repetitionCountTestB);
            return 1;
        }
    } else  {
        VERBOSE && printf("repetitionTest.B reset\n", repetitionCountTestB);
        repetitionCountTestA = sample;
        repetitionCountTestB = 1;
    }

    return 0;
}


/**
 * Create a very simple circular buffer to track samples as they
 * are processed. This is only used for debugging purposes and is
 * not part of the health testing algorithm.
 */
struct circularBuffer  {
    Sample buf[_W];
    int i;  /* insertion point */
    int n;  /* Current number of items in the buffer */
};
int cb_append(struct circularBuffer *cb, Sample c)  {
    cb->buf[cb->i] = c;
    cb->i = (cb->i + 1) % _W;
    if( cb->n >= _W ) cb->n = _W;
    else cb->n++;
    return 0;
}
int cb_clear(struct circularBuffer *cb)  {
    cb->n = 0;
    cb->i = 0;
    return 0;
}
int cb_print(struct circularBuffer *cb)  {
    /* Print out the circular buffer similar to the Python format */
    printf("[");
    int start = (cb->i == cb->n ? 0 : cb->i);
    for (int i = 0; i < cb->n-1; i ++) {
        printf("'%s', ", toBinaryValue(cb->buf[(start + i) % _W]));
    }
    /* Print last value, which must not have a comma */
    printf("'%s']\n", toBinaryValue(cb->buf[(start + cb->n-1) % _W]));
    return 0;
}


static Sample adaptiveProportionTestA = 0;
static unsigned int adaptiveProportionTestB = 1;
static unsigned int adaptiveProportionTestC = AdPC;
static unsigned int adaptiveProportionTestW = _W;
static unsigned int adaptiveProportionTestSampleN = 1;
static struct circularBuffer q; /* Everything init'd to 0 since static allocation */

int adaptiveProportionTest(Sample sample) {
    /**
     * The adaptive proportion test checks for repeated values within a 
     * specific window size (W) and is used to detect a large loss of entropy.
     * Returns zero if everything went well, else returns non-zero if there is a health
     * test failure.
     */

    /**
     * Note that while NIST 800-90B states the range is from 1..W-1, this
     * means [1..W) which is identical to 1 <= sampleN < W.
     * The purpose of this is that W samples are being used in the checks.
     * Since 1 sample is used as the seeding comparator, the loop proceeds for
     * W-1 additional sample checks against the comparator.  See paragraph 2 in 
     * NIST SP 800-90B section 4.4.2.
     * These next few lines actually represent the "for loop" the SP specifies, it's 
     * just that we are a re-entrant function.
     */
    if (adaptiveProportionTestSampleN < adaptiveProportionTestW)  {
        DEBUG && cb_append(&q, sample);
        adaptiveProportionTestSampleN ++;

        if (samplesAreEqual(sample, adaptiveProportionTestA))  {
            adaptiveProportionTestB++;
            DEBUG && printf("adaptiveProportionTest.B incremented to %u\n", adaptiveProportionTestB);
        }

        if (adaptiveProportionTestB >= adaptiveProportionTestC)  {
            DEBUG && cb_print(&q);
            printf("Sample %s repeats with threshold %u\n", toBinaryValue(adaptiveProportionTestA), adaptiveProportionTestB);
            return 1;
        }
    }
    else  { 
        VERBOSE && printf("adaptiveProportionTest.sampleN reset\n");
        adaptiveProportionTestSampleN = 1;
        adaptiveProportionTestB = 1;
        /* To be crystal clear here as to what 'sample' will be relative to
         * repeated calls, let's analyze the flow just when 
         * adaptiveProportionTestSampleN is about to exceed 
         * adaptiveProportionTestW.
         * So adaptiveProportionTestSampleN < adaptiveProportionTestW
         * continues to hold true so the 'if' branch above will run.
         * adaptiveProportionTestSampleN is incremented meaning that the
         * NEXT time this function is entered, the 'if' relation will no
         * longer hold.  However, the NEXT iteration will have a new
         * 'sample' value which is similar to 'A=next()' from Step 1
         * in the NIST SP Step 4 of the algorithm in 4.4.2.
         * 
         * At this point, this 'else' code path is entered and 'sample'
         * will be assigned to adaptiveProportionTestA but not used for any
         * other comparison purposes.
         * adaptiveProportionTestSampleN and adaptiveProportionTestSampleB
         * are reset to 1 and that will ultimately reset the window check
         * so that subsequent calls will enter the 'if' branch above.
         * 
         * Therefore, the logic shown here appears to match that given in
         * section 4.4.2.
         */
        adaptiveProportionTestA = sample;
        DEBUG && cb_clear(&q);
    }

    return 0;
}



int main(void)  {
    Sample sample = 0;
    int failToSample = 0;

    if (getenv("DEBUG") != NULL)  {
        VERBOSE = atoi(getenv("DEBUG")) >= 2;
        DEBUG = atoi(getenv("DEBUG")) >= 1;
    } else {
        DEBUG = VERBOSE = 0;
    }


    if ( getRawSample(stdin, &sample) == ENODATA ) failToSample++;
    repetitionCountTestA = sample;
    adaptiveProportionTestA = sample;

    while(1)  {
        if ( getRawSample(stdin, &sample) == ENODATA )  {
            failToSample ++;
            if (failToSample > 9)  {
                printf("Failed to capture sample from noise source.\n");
                goto error;
            }
            continue;
        }
        failToSample = 0;
        if (repetitionCountTest(sample) != 0)
            goto error;
        if (adaptiveProportionTest(sample) != 0)
            goto error;
        
        /* From here, we can forward the entropy sample onward to the pool. */
        /* ... */
    }

error:
    printf("System halting due to entropy health testing error.\n");
    return 1;
}


/**
 * Creative Commons Legal Code
 * 
 * CC0 1.0 Universal
 * 
 *     CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE
 *     LEGAL SERVICES. DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN
 *     ATTORNEY-CLIENT RELATIONSHIP. CREATIVE COMMONS PROVIDES THIS
 *     INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO WARRANTIES
 *     REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS
 *     PROVIDED HEREUNDER, AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM
 *     THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED
 *     HEREUNDER.
 * 
 * Statement of Purpose
 * 
 * The laws of most jurisdictions throughout the world automatically confer
 * exclusive Copyright and Related Rights (defined below) upon the creator
 * and subsequent owner(s) (each and all, an "owner") of an original work of
 * authorship and/or a database (each, a "Work").
 * 
 * Certain owners wish to permanently relinquish those rights to a Work for
 * the purpose of contributing to a commons of creative, cultural and
 * scientific works ("Commons") that the public can reliably and without fear
 * of later claims of infringement build upon, modify, incorporate in other
 * works, reuse and redistribute as freely as possible in any form whatsoever
 * and for any purposes, including without limitation commercial purposes.
 * These owners may contribute to the Commons to promote the ideal of a free
 * culture and the further production of creative, cultural and scientific
 * works, or to gain reputation or greater distribution for their Work in
 * part through the use and efforts of others.
 * 
 * For these and/or other purposes and motivations, and without any
 * expectation of additional consideration or compensation, the person
 * associating CC0 with a Work (the "Affirmer"), to the extent that he or she
 * is an owner of Copyright and Related Rights in the Work, voluntarily
 * elects to apply CC0 to the Work and publicly distribute the Work under its
 * terms, with knowledge of his or her Copyright and Related Rights in the
 * Work and the meaning and intended legal effect of CC0 on those rights.
 * 
 * 1. Copyright and Related Rights. A Work made available under CC0 may be
 * protected by copyright and related or neighboring rights ("Copyright and
 * Related Rights"). Copyright and Related Rights include, but are not
 * limited to, the following:
 * 
 *   i. the right to reproduce, adapt, distribute, perform, display,
 *      communicate, and translate a Work;
 *  ii. moral rights retained by the original author(s) and/or performer(s);
 * iii. publicity and privacy rights pertaining to a person's image or
 *      likeness depicted in a Work;
 *  iv. rights protecting against unfair competition in regards to a Work,
 *      subject to the limitations in paragraph 4(a), below;
 *   v. rights protecting the extraction, dissemination, use and reuse of data
 *      in a Work;
 *  vi. database rights (such as those arising under Directive 96/9/EC of the
 *      European Parliament and of the Council of 11 March 1996 on the legal
 *      protection of databases, and under any national implementation
 *      thereof, including any amended or successor version of such
 *      directive); and
 * vii. other similar, equivalent or corresponding rights throughout the
 *      world based on applicable law or treaty, and any national
 *      implementations thereof.
 * 
 * 2. Waiver. To the greatest extent permitted by, but not in contravention
 * of, applicable law, Affirmer hereby overtly, fully, permanently,
 * irrevocably and unconditionally waives, abandons, and surrenders all of
 * Affirmer's Copyright and Related Rights and associated claims and causes
 * of action, whether now known or unknown (including existing as well as
 * future claims and causes of action), in the Work (i) in all territories
 * worldwide, (ii) for the maximum duration provided by applicable law or
 * treaty (including future time extensions), (iii) in any current or future
 * medium and for any number of copies, and (iv) for any purpose whatsoever,
 * including without limitation commercial, advertising or promotional
 * purposes (the "Waiver"). Affirmer makes the Waiver for the benefit of each
 * member of the public at large and to the detriment of Affirmer's heirs and
 * successors, fully intending that such Waiver shall not be subject to
 * revocation, rescission, cancellation, termination, or any other legal or
 * equitable action to disrupt the quiet enjoyment of the Work by the public
 * as contemplated by Affirmer's express Statement of Purpose.
 * 
 * 3. Public License Fallback. Should any part of the Waiver for any reason
 * be judged legally invalid or ineffective under applicable law, then the
 * Waiver shall be preserved to the maximum extent permitted taking into
 * account Affirmer's express Statement of Purpose. In addition, to the
 * extent the Waiver is so judged Affirmer hereby grants to each affected
 * person a royalty-free, non transferable, non sublicensable, non exclusive,
 * irrevocable and unconditional license to exercise Affirmer's Copyright and
 * Related Rights in the Work (i) in all territories worldwide, (ii) for the
 * maximum duration provided by applicable law or treaty (including future
 * time extensions), (iii) in any current or future medium and for any number
 * of copies, and (iv) for any purpose whatsoever, including without
 * limitation commercial, advertising or promotional purposes (the
 * "License"). The License shall be deemed effective as of the date CC0 was
 * applied by Affirmer to the Work. Should any part of the License for any
 * reason be judged legally invalid or ineffective under applicable law, such
 * partial invalidity or ineffectiveness shall not invalidate the remainder
 * of the License, and in such case Affirmer hereby affirms that he or she
 * will not (i) exercise any of his or her remaining Copyright and Related
 * Rights in the Work or (ii) assert any associated claims and causes of
 * action with respect to the Work, in either case contrary to Affirmer's
 * express Statement of Purpose.
 * 
 * 4. Limitations and Disclaimers.
 * 
 *  a. No trademark or patent rights held by Affirmer are waived, abandoned,
 *     surrendered, licensed or otherwise affected by this document.
 *  b. Affirmer offers the Work as-is and makes no representations or
 *     warranties of any kind concerning the Work, express, implied,
 *     statutory or otherwise, including without limitation warranties of
 *     title, merchantability, fitness for a particular purpose, non
 *     infringement, or the absence of latent or other defects, accuracy, or
 *     the present or absence of errors, whether or not discoverable, all to
 *     the greatest extent permissible under applicable law.
 *  c. Affirmer disclaims responsibility for clearing rights of other persons
 *     that may apply to the Work or any use thereof, including without
 *     limitation any person's Copyright and Related Rights in the Work.
 *     Further, Affirmer disclaims responsibility for obtaining any necessary
 *     consents, permissions or other rights required for any use of the
 *     Work.
 *  d. Affirmer understands and acknowledges that Creative Commons is not a
 *     party to this document and has no duty or obligation with respect to
 *     this CC0 or use of the Work.
 */
