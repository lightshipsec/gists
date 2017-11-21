#!/usr/bin/env python

#
# Originally authored by Greg McLearn at Lightship Security, Inc.
#
# Sample NIST SP800-90B revision 2 mandatory  health tests.  The code is written
# in such a way as to ensure that both health tests are running continuously and 
# simultaneously.
#
# To the extent possible under law, the author(s)  have dedicated  all copyright 
# and  related and  neighboring rights  to  this software  to the  public domain 
# worldwide. This software is distributed without any warranty.
# You should have received a copy of the CC0 Public Domain Dedication along with
# this software.  If not, see http://creativecommons.org/publicdomain/zero/1.0/.
#
# See legal wording at end of this file.
#

#
# Here is one way to test this on the command-line in  which  we introduce  a 
# catastrophic RNG failure by biasing on bit pattern 00000000.
# To make this fail faster, change divisor from 50 to something else, like 2.
#
"""
python - <<EOT | DEBUG=1 python NIST\ SP800-90B\ draft\ 2\ Health\ Tests.py
import sys, random, time
random.seed(time.time())
while True:
   b=int(random.random()*256)
   if not b%50:
       sys.stdout.write(chr(0))
   else:
       sys.stdout.write(chr(b))
EOT
""" 

# Originally written for Python 2.7
from __future__ import print_function
import os, sys, math, collections

try:
    VERBOSE = True if int(os.environ['DEBUG']) >= 2 else False
    DEBUG   = True if int(os.environ['DEBUG']) >= 1 else False
except:
    VERBOSE = False
    DEBUG = False


# These are the values that the implementor needs to determine.
# H is determined by quantitative/statistical analysis of the entropy
# samples. W is set based on whether the entropy samples are binary
# (then W = 1024) or non-binary (then W = 512).  See paragraphs 918
# and 919 in NIST SP800-90B draft 2.

H = 7.8             # From entropy analysis, min-entropy 
                    # (this is an example only and is not indicative of the 
                    # entropy in general.

W = 512             # From review of entropy samples it is NOT binary data
                    # (mainly because we are reading and understanding bytes)

AdPC = 19           # Using Excel, calculate once and fix the value:
                    # =CRITBINOM(W, power(2,(-H)),1-power(2,(-40)) 
                    # as per footnote 4 in paragraph 936 in NIST SP800-90B 
                    # draft 2


def getRawSample(noise):
    """Get a single raw entropy noise sample. In our example, the sample is a 
    byte.
    """
    b = noise.read(1)
    if len(b) == 0:
        VERBOSE and print('Failed to capture sample from noise source.')
        return None
    VERBOSE and print('Noise sample {0:08b}'.format(ord(b)))
    return b

def samplesAreEqual(sample1, sample2):
    """Simply provide some way to compare for equality. In our example, we 
    compare two bytes.  This function is present only to illustrate that
    comparisons might actually be less than trivial.
    """
    return sample1 == sample2



class HealthTestError(Exception):
    pass
class RepetitionError(HealthTestError):
    pass
class NoiseSourceReadError(Exception):
    pass


def repetitionTest(sample):
    """The repetition test is like an updated version of the stuck-bit test as 
    per NIST SP800-90B, draft 2.
    """
    if samplesAreEqual(sample, repetitionTest.A):
        repetitionTest.B += 1
        DEBUG and print("repetitionTest.B incremented to {}".format(repetitionTest.B))
        if repetitionTest.B == repetitionTest.C:
            raise RepetitionError("Sample {:08b} repeats with threshold {}".format(ord(sample), repetitionTest.B))
    else:
        VERBOSE and print("repetitionTest.B reset".format(repetitionTest.B))
        repetitionTest.A = sample
        repetitionTest.B = 1


#
# Use a container to hold into the last W values to help in debugging and 
# understanding context when a failure occurs.
#
if DEBUG:
    q = collections.deque(maxlen = W)

def adaptiveProportionTest(sample):
    """The adaptive proportion test checks for repeated values within a 
    specific window size (W) and is used to detect a large loss of entropy.
    """

    DEBUG and q.append(sample)

    # Note that while NIST 800-90B draft 2 states the range is from 1..W-1, this
    # means [1..W) which is identical to 1 <= sampleN < W.
    # These next few lines actually represent the "for loop" the SP specifies, it's 
    # just that we are a re-entrant function.
    if adaptiveProportionTest.sampleN < W:
        adaptiveProportionTest.sampleN += 1
        if samplesAreEqual(sample, adaptiveProportionTest.A):
            adaptiveProportionTest.B += 1
            DEBUG and print("adaptiveProportionTest.B incremented to {}".format(adaptiveProportionTest.B))
    else:
        # Once the loop is done, we check how the window fared.
        # It is unclear why we need to check to the end of the window, however.
        # If we encountered a large loss of entropy before the window size was
        # up, then we could exit earlier.  However, the algorithm from
        # paragraphs 923 to 928 implies the check is performed only after the
        # window loop is completed.  I think it is equivalent to exit earlier,
        # in which case this check can be moved outside of and below this `else'
        # statement.
        if adaptiveProportionTest.B > adaptiveProportionTest.C:
            DEBUG and print("{}".format(["{:08b}".format(ord(i)) for i in q]))
            raise RepetitionError("Sample {:08b} repeats with threshold {}".format(ord(adaptiveProportionTest.A), adaptiveProportionTest.B))

        VERBOSE and print("adaptiveProportionTest.sampleN reset")
        adaptiveProportionTest.sampleN = 1
        adaptiveProportionTest.B = 1
        adaptiveProportionTest.A = sample
        DEBUG and q.clear()



# Get an initial bootstrap sample
sample = getRawSample(sys.stdin)

# Initialize to the required values in NIST SP800-90B, draft 2
repetitionTest.A = sample
repetitionTest.B = 1
# 40 comes from log_2(2^(-40)), as per paragraph 867, this is a reasonable 
# choice; an implementer might want to adjust depending on their risk
# requirements, but it isn't something vendors are likely to want to play
# too much with unless they understand the ramifications.
repetitionTest.C = int(math.ceil(1 + (40 / H)))

adaptiveProportionTest.A = sample
adaptiveProportionTest.B = 1
adaptiveProportionTest.C = AdPC 
adaptiveProportionTest.W = W
adaptiveProportionTest.sampleN = 1

# We will also track cases in which the noise source fails to provide any 
# data at all.  Bootstrap with the result of the initial sample result.
failToSample = (1 if sample is None else 0)

while True:
    # Our infinite loop simulates entropy continuously being fed to the
    # health tests.
    sample = getRawSample(sys.stdin)

    try:
        if not sample:
            # No entropy sample received; continue to read
            failToSample += 1
            if failToSample > 9:
                raise NoiseSourceReadError("Failed to capture sample from noise source.")
            continue

        failToSample = 0
        repetitionTest(sample)
        adaptiveProportionTest(sample)

        # From here, we can forward the entropy sample onward to the pool.
        # ...
    except HealthTestError as e:
        print(e)
        break
    except Exception as e:
        print(e)
        break


print("System halting due to entropy health testing error.")
sys.exit(1)


# Creative Commons Legal Code
# 
# CC0 1.0 Universal
# 
#     CREATIVE COMMONS CORPORATION IS NOT A LAW FIRM AND DOES NOT PROVIDE
#     LEGAL SERVICES. DISTRIBUTION OF THIS DOCUMENT DOES NOT CREATE AN
#     ATTORNEY-CLIENT RELATIONSHIP. CREATIVE COMMONS PROVIDES THIS
#     INFORMATION ON AN "AS-IS" BASIS. CREATIVE COMMONS MAKES NO WARRANTIES
#     REGARDING THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS
#     PROVIDED HEREUNDER, AND DISCLAIMS LIABILITY FOR DAMAGES RESULTING FROM
#     THE USE OF THIS DOCUMENT OR THE INFORMATION OR WORKS PROVIDED
#     HEREUNDER.
# 
# Statement of Purpose
# 
# The laws of most jurisdictions throughout the world automatically confer
# exclusive Copyright and Related Rights (defined below) upon the creator
# and subsequent owner(s) (each and all, an "owner") of an original work of
# authorship and/or a database (each, a "Work").
# 
# Certain owners wish to permanently relinquish those rights to a Work for
# the purpose of contributing to a commons of creative, cultural and
# scientific works ("Commons") that the public can reliably and without fear
# of later claims of infringement build upon, modify, incorporate in other
# works, reuse and redistribute as freely as possible in any form whatsoever
# and for any purposes, including without limitation commercial purposes.
# These owners may contribute to the Commons to promote the ideal of a free
# culture and the further production of creative, cultural and scientific
# works, or to gain reputation or greater distribution for their Work in
# part through the use and efforts of others.
# 
# For these and/or other purposes and motivations, and without any
# expectation of additional consideration or compensation, the person
# associating CC0 with a Work (the "Affirmer"), to the extent that he or she
# is an owner of Copyright and Related Rights in the Work, voluntarily
# elects to apply CC0 to the Work and publicly distribute the Work under its
# terms, with knowledge of his or her Copyright and Related Rights in the
# Work and the meaning and intended legal effect of CC0 on those rights.
# 
# 1. Copyright and Related Rights. A Work made available under CC0 may be
# protected by copyright and related or neighboring rights ("Copyright and
# Related Rights"). Copyright and Related Rights include, but are not
# limited to, the following:
# 
#   i. the right to reproduce, adapt, distribute, perform, display,
#      communicate, and translate a Work;
#  ii. moral rights retained by the original author(s) and/or performer(s);
# iii. publicity and privacy rights pertaining to a person's image or
#      likeness depicted in a Work;
#  iv. rights protecting against unfair competition in regards to a Work,
#      subject to the limitations in paragraph 4(a), below;
#   v. rights protecting the extraction, dissemination, use and reuse of data
#      in a Work;
#  vi. database rights (such as those arising under Directive 96/9/EC of the
#      European Parliament and of the Council of 11 March 1996 on the legal
#      protection of databases, and under any national implementation
#      thereof, including any amended or successor version of such
#      directive); and
# vii. other similar, equivalent or corresponding rights throughout the
#      world based on applicable law or treaty, and any national
#      implementations thereof.
# 
# 2. Waiver. To the greatest extent permitted by, but not in contravention
# of, applicable law, Affirmer hereby overtly, fully, permanently,
# irrevocably and unconditionally waives, abandons, and surrenders all of
# Affirmer's Copyright and Related Rights and associated claims and causes
# of action, whether now known or unknown (including existing as well as
# future claims and causes of action), in the Work (i) in all territories
# worldwide, (ii) for the maximum duration provided by applicable law or
# treaty (including future time extensions), (iii) in any current or future
# medium and for any number of copies, and (iv) for any purpose whatsoever,
# including without limitation commercial, advertising or promotional
# purposes (the "Waiver"). Affirmer makes the Waiver for the benefit of each
# member of the public at large and to the detriment of Affirmer's heirs and
# successors, fully intending that such Waiver shall not be subject to
# revocation, rescission, cancellation, termination, or any other legal or
# equitable action to disrupt the quiet enjoyment of the Work by the public
# as contemplated by Affirmer's express Statement of Purpose.
# 
# 3. Public License Fallback. Should any part of the Waiver for any reason
# be judged legally invalid or ineffective under applicable law, then the
# Waiver shall be preserved to the maximum extent permitted taking into
# account Affirmer's express Statement of Purpose. In addition, to the
# extent the Waiver is so judged Affirmer hereby grants to each affected
# person a royalty-free, non transferable, non sublicensable, non exclusive,
# irrevocable and unconditional license to exercise Affirmer's Copyright and
# Related Rights in the Work (i) in all territories worldwide, (ii) for the
# maximum duration provided by applicable law or treaty (including future
# time extensions), (iii) in any current or future medium and for any number
# of copies, and (iv) for any purpose whatsoever, including without
# limitation commercial, advertising or promotional purposes (the
# "License"). The License shall be deemed effective as of the date CC0 was
# applied by Affirmer to the Work. Should any part of the License for any
# reason be judged legally invalid or ineffective under applicable law, such
# partial invalidity or ineffectiveness shall not invalidate the remainder
# of the License, and in such case Affirmer hereby affirms that he or she
# will not (i) exercise any of his or her remaining Copyright and Related
# Rights in the Work or (ii) assert any associated claims and causes of
# action with respect to the Work, in either case contrary to Affirmer's
# express Statement of Purpose.
# 
# 4. Limitations and Disclaimers.
# 
#  a. No trademark or patent rights held by Affirmer are waived, abandoned,
#     surrendered, licensed or otherwise affected by this document.
#  b. Affirmer offers the Work as-is and makes no representations or
#     warranties of any kind concerning the Work, express, implied,
#     statutory or otherwise, including without limitation warranties of
#     title, merchantability, fitness for a particular purpose, non
#     infringement, or the absence of latent or other defects, accuracy, or
#     the present or absence of errors, whether or not discoverable, all to
#     the greatest extent permissible under applicable law.
#  c. Affirmer disclaims responsibility for clearing rights of other persons
#     that may apply to the Work or any use thereof, including without
#     limitation any person's Copyright and Related Rights in the Work.
#     Further, Affirmer disclaims responsibility for obtaining any necessary
#     consents, permissions or other rights required for any use of the
#     Work.
#  d. Affirmer understands and acknowledges that Creative Commons is not a
#     party to this document and has no duty or obligation with respect to
#     this CC0 or use of the Work.
# 
