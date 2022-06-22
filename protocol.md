# Homa Protocol Synopsis

This file contains a terse summary of the packet protocol used by this
driver for communication between client and server machines.

## Basics
Homa implements RPCs (remote procedure calls), in which a client sends
a *request message* to a server, the server carries out an operation
described in the request message, and then the server returns a
*response message* to the client. Each message contains one or more
packets of data.

## Packet types
Homa supports the following packet types; for complete details, see the
declarations in homa_impl.h.

**DATA**: contains a contiguous range of bytes from a message, along with
additional metadata such as the total length of the message, and the
total number of bytes of the message that the sender will transmit
without additional grants.

**GRANT**: sent by receivers to authorize senders to send additional
bytes of the message. Contains the total number of bytes of the message
the sender is now permitted to transmit, along with the priority to use in
any future DATA packets for this message.

**RESEND**: sent by receivers to request that the sender retransmit a
given range of bytes of the message; also includes the priority to use
for the retransmitted data.

**UNKNOWN**: sent by either sender or receiver when it receives
a packet for an RPC that is unknown to it.

**BUSY**: sent as a response to a RESEND packet when the sender is not
willing to transmit data for this message right now (e.g. because it has
other higher-priority messages to transmit). Used to prevent timeouts.

**CUTOFFS**: contains new values for the priority cutoffs the recipient
should use when sending unscheduled bytes.

**FREEZE**: used for debugging and performance analysis: causes the
recipient to freeze its timetrace.

**NEED_ACK**: sent by servers to ask that a client explicitly acknowledge
receipt of the response for an RPC.

**ACK**: sent by a client to acknowledge that it has received responses
for one or more RPCs, so the server can discard its state for that RPC.

## Basics of an RPC
When a client wishes to initiate an RPC, it transmits the request message to the
RPC's server using one or more DATA packets. A client is allowed to transmit
the first bytes of a message unilaterally, without permission; these bytes are
called *unscheduled bytes*. After that, additional packets may only be
transmitted when authorized by GRANT packets received from the server. The
number of unscheduled bytes is determined by the `rtt_bytes` configuration
parameter; its value is normally chosen so that by the time all of the unscheduled
bytes have been transmitted, there will have been enough time for the first
DATA packet to have reached the receiver and for it to have returned a
GRANT packet. This means that a single message can consume the entire
link bandwidth of the sender if the system is unloaded. If the number of
unscheduled bytes does not represent an integral number of full DATA packets, it is
rounded up to the next full packet boundary; likewise for grants.

Once the server has received the request, it passes that message up to
the application. Eventually the application returns a response message,
which the server transmits back to the client using the same protocol
as for the request.

## Retransmission
Retransmission is driven by the receiver of a message (the server for requests
and the client for responses). If a timeout period elapses during which the
receiver has 
