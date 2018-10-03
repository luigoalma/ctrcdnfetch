ctrcdnfetch
===========

This tool allows an user to download content from Nintendo CDN without a 3DS after extra server-side checks were added for 11.8+.\
**This will require the user to have signed tickets for the target content.**

**A little warning,** like the 3DS, it will send the signed ticket encrypted in a wrapper. Otherwise it's impossible to access content.\
So be aware the servers will have hold of your ticket everytime you send it, and unique eshop tickets come with **console and account ids.**

*This tool is not required for system titles. Any other tool can access those titles without a ticket, they can't add checks to these titles since it would break system updates for older versions.*

License
-------

The tool itself is under MIT. Read [LICENSE](LICENSE).

Other useful tools
------------------

[**d0k3's GodMode9**](https://github.com/d0k3/GodMode9) to dump tickets.\
[**make_cdn_cia v1.1**](https://github.com/llakssz/make_cdn_cia) to make cias out of downloaded content.

Example usage
-------------

Let's say we have ticket file named `0004000000DEAD00.tik`, user may run tool like:
>ctrcdnfetch 0004000000DEAD00.tik

If the user wants to add a proxy to the connection, they may add the argument `-p URI` or `--proxy URI`
>ctrcdnfetch --proxy https://example.org 0004000000DEAD00.tik
*run `ctrcdnfetch --help` for proxy examples*

Building from source
--------------------

### Requirements:

+ C++11 Compatible compiler (I recommend [GCC](https://www.gnu.org/software/gcc))
+ [Binutils](https://www.gnu.org/software/binutils)
+ [Openssl v1.1+](https://www.openssl.org)
+ [libcurl v7.55+](https://curl.haxx.se)

### Building:

Run `make` if `g++` and `strip` are in `$PATH` (or `%PATH%` on windows) and libraries and headers are in g++'s search paths.

If extra compiler flags or libs are needed, `EXTRA_CXXFLAGS` and `EXTRA_LIBS` may be specified:
>make EXTRA_CXXFLAGS="-DEXAMPLE" EXTRA_LIBS="-lexample"

If `g++` and `strip` have a prefix on their names, you can add `TOOLCHAIN_PREFIX` also:
>make TOOLCHAIN_PREFIX="x86_64-pc-example-"

If you need to completely overwrite the compiler, strip tool, as well flags and libs, you can overwrite with `GXX`, `STRIP`, `CXXFLAGS` and `LIBS`, respectively.
