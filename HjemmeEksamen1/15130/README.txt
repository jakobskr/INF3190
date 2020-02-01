How to run:
The easiest way to compile is to use the supplied makefile.
make daemon
make pingc
make pings
make ruter
and to run the program you can use the following commands:
./daemon [-h] [-d] <socket_application>  <routing_socket> <forward_socket> [mip_adresses]
./pings [-h] <socket_application>
./pingc [-h] <mip_destination> <message> <socket_application>
./ruter [-h] <routing_socket> <forward_socket>
NB: mip_addresses must be in the range of 0-254.
NB: the message length INCLUDING the terminating NULL byte must be a multiple of 4, I.E “HEL” and not “hell”
NB: the help command does not execute the program, but only prints the help text.
