# Tap based strategy.
In this scenario we can use the google gonet package, which emulates networking stacks in userspace,
to connect to a raw tap device, and serve that way. Ideally, we would be able to remap arbitrary packets
to ports we are using, and that way archive a variety of network packets.
As of right now it is still in minimum-viable state. The testing strategy was to:
* create a new net ns
* create a veth pair between the net ns's
* create a tap device in the main net ns
* create a bridge device in the main net ns
* add the tap and veth to the bridge
* bring them all up
* run meadtap on the tap device
* assign the tap device in the new net ns an address
* meadtap should terminate tls and proxy tls connections appropriately
## TODO is resolution. Right now mead does no DNS for the alternate ns
