# Generate Microsoft Security Catalog (.cat) files

When building Windows drivers for 64 bit versions of Windows
a Microsoft Security Catalog (``.cat``) file is required when
the driver is added to the driver store. This file contains
SHA1 hashes of other files used by the driver (usually the
``mydriver.sys`` and the ``mydriver.inf`` file). To date as of my
knowledge there is no open source implementation that does
not depend on the ``wintrust.dll`` library (which would require
either a Windows build machine or wine which unfortunately
does not implement this particular feature). So I wrote
a small C program from scratch that creates the ``.cat``
file.

## Usage

You would normally use the utility via the gencat.sh
(bash) shell script as follows:

    ./gencat.sh -o mydriver.cat -h myhardwareID mydriver.inf mydriver.sys

So for (example) WinDRBD the command line would be:

    generate-cat-file/gencat.sh -o windrbd.cat-unsigned -h windrbd windrbd.inf windrbd.sys

Note that the gencat just generates the cat file with the
SHA1 hashes of the files you specify on the command line
(``mydriver``.inf and ``mydriver.sys`` in our example). It does
not sign the ``.cat`` file. Signing a cat file (and also a
``.sys`` file) can be done with the ``osslsigncode`` utility,
which is also open source and runs on Linux. Be sure to
pick a modern (2022) version of ``osslsigncode`` since
``.cat`` file support was only added recently.

## Building the C programs

There are two C programs: ``generate-cat-file.c`` and
``strip-pe-image``. To compile them any C compiler
that supports the C99 standard (required for the
bool datatype) should be sufficient. There are no
library dependencies for the C programs. To build
them run (from the project root file):

    make

To install them on your system, do

    sudo make install

which would install it into ``/usr/local/bin``.

The only other dependency that comes to my mind is
that the ``sha1sum`` utility must be installed on
your system which is usually the case.

## About the .cat file format

Cat files are at least in theory PKCS7 encoded
binary files which are described in ASN.1 syntax.
ASN.1 is a meta language for data structures that
originates in the early 1980's when every single
byte counted. Therefore it is a rather complex
data structure. Furthermore there are different
encodings on the binary level for this data
structure. ``.cat`` files use the ASN.1 DER format.

Instead of reading through the various definitions
I used a (publically available) ASN.1 DER parser
written in Java script to understand the format.
The URL of this parser is:

    http://lapo.it/asn1js/

Furthermore this introduction to the DER encoding
was very useful:

    https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

As a last step it was neccessary to strip existing
signatures and their checksums from a ``.sys`` file
(which is similar to an ``.exe`` file) when the
SHA1 checksum was computed. This allows for changing
signatures in the ``.sys`` file later without having
to rebuild the ``.cat`` file.

