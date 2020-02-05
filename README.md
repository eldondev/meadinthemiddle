# meadinthemiddle - a man-in-the-middle generic proxy

Inspiration or blatant code reuse: 
https://github.com/kr/mitm
https://github.com/paultag/sniff

**Install**

go get github.com/eldondev/meadinthemiddle


**Why?**

When building containers, there is a strange and unfortunate byproduct of the
modern age, where, rather than operating one or two package managers, operators
might end up operating _many_ package managers, and downloading a huge variety
of resources, some of which go over http, and some of which might go over
https.  In the interest of extreme caching of these https resources in addition
to the regular http resources (ahhh, apt-cacher), it would be very nice to be
able to mitm the systems in the build security context, and avoid pulling random
docker images 10k times every time you cycle a jenkins box.

The above two projects each bring something valuable to the table. kr's mitm has the code
to generate certificates on the fly. However, it expects to interact via either an unencrypted
http request, or a CONNECT statement. Hitting it directly with an SNI header is a no-go, as it didn't have
the capability to parse out the request header. paultag's sniff repo is the other half of the puzzle,
it loads a plain socket connection, and routes based on SNI. This project rips out the SNI parsing code, simulates 
a CONNECT to the mitm bits, and then shoves all of this through intertubes to get the client something meaningful.

Wait, didn't we have something to say about caching here? Yeah, well.... maybe tomorrow.

