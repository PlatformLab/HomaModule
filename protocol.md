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
additional metadata such as the total length of the message and the
total number of bytes of the message that the sender will transmit
without additional grants.

**GRANT**: sent by receivers to authorize the sender to transmit additional
bytes of the message. Contains the total number of (leading) bytes of the message
the sender is now permitted to transmit, along with the priority level to use in
future DATA packets for this message.

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

**FREEZE**: causes the recipient to freeze its internal timetrace; used
for debugging and performance analysis. This packet type is not discussed here.

**NEED_ACK**: sent by servers to ask that a client explicitly acknowledge
receipt of the response for a particular RPC.

**ACK**: sent by a client to acknowledge that it has received responses
for one or more RPCs, so the server can discard its state for those RPCs.

## Basics of an RPC
When a client wishes to initiate an RPC, it transmits the request message to the
server using one or more DATA packets. A client is allowed to transmit
the first bytes of a message unilaterally, without permission; these bytes are
called *unscheduled bytes*. After that, additional packets may only be
transmitted when authorized by GRANT packets sent by the server. The
number of unscheduled bytes is determined by the `rtt_bytes` configuration
parameter; its value is normally chosen so that by the time all of the unscheduled
bytes have been transmitted, there will have been enough time for the first
DATA packet to have reached the receiver and for it to have returned a
GRANT packet.
As it receives DATA packets, the server sends GRANT packets so as to
maintain `rtt_bytes` of granted but not yet received data.
This means that a single message can consume the entire
link bandwidth of the sender if the system is unloaded. If the number of
unscheduled bytes does not represent an integral number of full DATA packets,
the sender rounds it up to the next full packet boundary; likewise for grants.

Note: in networks with nonuniform round-trip times (e.g. most datacenter
fabrics), `rtt_bytes` should be calculated on a peer-to-peer basis to
reflect the round-trip times between that pair of machines. This feature
is not currently implemented: Homa uses a single value of `rtt_bytes` for
all peers.

Once the server has received the request, it passes that message up to
the application. Eventually the application returns a response message,
which the server transmits back to the client using the same protocol
as for the request.

## Retransmission
Retransmission is driven by the receiver of a message, which is the
server for requests and the client for responses. If a timeout period elapses
during which the receiver has received no DATA, GRANT, or BUSY packets
related to the message, it sends a RESEND packet, asking the sender
to retransmit the first unreceived range of bytes within the message.
If several RESENDS are issued with no response, the receiver concludes
that the peer has crashed and it aborts the RPC; this means freeing
all the state associated with the RPC and (on the client) notifying the
application that the RPC has failed.

A receiver only issues RESENDs if it is actually expecting incoming
data: it will not issue a RESEND if all granted data for the message has
been received.

The sender may not be in a position to respond to a RESEND request
immediately (for example, it may wish to prioritize transmission of
other messages). In this case, it returns a BUSY packet to let the
receiver know that it is alive and intentionally not transmitting;
this causes the receiver to reset its timeout.

If all of the packets sent by a client to a server are lost, then
the server will have no record of the RPC so it cannot request
retransmission. However, a timeout will still occur on the client
because it received no packets from the server for that RPC; when
that happens, the client sends a RESEND packet for the first bytes of the
response (which it has not received). When the server receives a
RESEND for an RPC that is unknown to it, it returns an UNKNOWN
packet in response; this tells the client that the server has no record
of the RPC, so the client retransmits the unscheduled data for the
request message.

Actual dropped packets are very rare, so when a RESEND is issued, the
cause is likely to be overload on the other end. If many RPCs to the
same peer all timeout, it's almost certainly because the peer is
overloaded, so we don't want to it make its overload even worse by sending
lots of RESENDs for it to process.
Because of this, Homa only issues one outstanding RESEND to
a given peer at a time; it rotates the RESENDs among the RPCs
to that peer (see comments in homa_timer.c for the reasoning behind
this). If enough timeouts occur to conclude that a peer has crashed,
then Homa aborts all RPCs for that peer.

## Server state cleanup
Homa ensures at-most-once semantics for RPCs. In order to achieve this,
a server must not discard its state for an RPC until it knows that the
client has received the result. At some point after it receives the
response for an RPC, the client will send an explicit *ack* to the
server, indicating that the server can safely discard its state for
the RPC. Acks can get sent in two ways. First, each DATA packet
has room for one ack, so if a client is having an ongoing conversation
with a server, it can use future RPCs to ack older ones. Second, clients
can send explicit ACK packets, each of which can carry multiple acks.
A client has limited storage for acks for each peer, so it will send
an ACK packet if its storage for a peer overflows. In addition, the server
will use its timeout mechanism to request an explicit ack if all of the
data has been transmitted for a response but no ack has been received.
The server sends a NEED_ACK packet to request the ack, and the client
will then respond with an ACK packet.

## Priorities
Homa attempts to implement an SRPT (shortest remaining processing time)
priority mechanism as closely as possible, favoring messages that
have the fewest bytes remaining to transmit.
One of the ways it achieves this is by taking advantage of switch priority
queues. The priority for each packet is
specified by the sender, using fields in the packet header.
However, the values of the priorities are controlled
by receivers.
For scheduled packets, receivers
compute priorities "just in time" and transmit the priority information to
senders in GRANT packets (see below for more details).
For unscheduled packets, senders notify
receivers in advance how to allocate priorities based on message lengths.
These allocations are updated from time to time based on traffic
observations made by each receiver.
Senders must maintain separate unscheduled priority cutoffs for
each receiver.

The priority allocation mechanism is driven by statistics on the sizes of
incoming messages.
First, priorities are divided between unscheduled and scheduled
packets so that the ratio of unscheduled/scheduled priorities approximates
the ratio of unscheduled/scheduled traffic (measured in bytes per second).
The highest priorities are used for unscheduled messages.
Then, the unscheduled priorities are divided based on message length, with
higher priorities used for shorter messages.
The cutoffs between priority levels are chosen to balance
the amount of incoming traffic in each priority level.
See the code in util/homa_prio.cc for details.

Once the cutoffs for unscheduled priorities are chosen, they are
transmitted to senders using CUTOFFS packets. The unscheduled priority
allocations are recomputed occasionally to reflect workload changes.

The use of priorities for scheduled packets is discussed in the next
section below.

All control packets (packet type other than DATA) are sent at the highest
priority level.

## Grants and overcommitment
When a receiver has multiple incoming messages that need grants, it does
not necessarily grant to all of them simultaneously. Restricting grants
to a subset of incoming messages helps with the implementation of SRPT
and also reduces buffer occupancy in network switches.
An extreme approach would be to grant to only a single incoming message
at a time (the one with the fewest bytes remaining to transmit).
However, there is no guarantee that a sender will transmit bytes
immediately when granted (it may choose to use its uplink bandwidth
for higher priority messages, as described in the next section).
If this were to happen, then the receiver's link could end up idle
even if there are other messages that could potentially use the bandwidth.
Under some workloads, this can result in as much as 40% of network
bandwidth being wasted.

Thus Homa implements *overcommitment*, where it grants to a few
messages at any given point in time. The goal is to grant to enough
messages that it is very likely that at least one of the senders
will transmit. The maximum number of messages to grant at any given
time is called the *degree of overcommitment*; it is specified
by the `max_overcommit` parameter, which is typically 8.

The actual grant mechanism is not driven directly by `max_overcommit`;
instead, Homa multiples `max_overcommit` by `rtt_bytes` to compute a
value called `max_incoming`. This sets a limit on the total number
of bytes that the receiver knows are incoming but has not yet received.
The actual number of incoming bytes consists of those that have been
granted but not yet received, plus unscheduled bytes that have not
yet been received.
Whenever a packet is received, Homa updates its estimate of the
actual incoming bytes; this can cause the actual incoming bytes to
either decrease (if a granted packet arrives) or increase (if
the first packet of a new message arrives, thereby indicating more
unscheduled bytes on the way).
The actual incoming bytes can grow arbitrarily large if many new messages
start arriving simultaneously.

Homa issues new grants only when the actual number of incoming bytes
is less than `max_incoming`.
To do this, Homa scans its incoming messages in decreasing
priority order, except that it considers at most
one message from each sender (there is no point in granting to
multiple messages from the same sender, since we know the sender will
only transmit packets from the message with higher priority).
For each message, if that message is not fully granted (i.e.,
fewer than `rtt_bytes` of data have been granted but not yet
received), then
a GRANT packet is sent to the sender. This process continues as
long as actual incoming bytes is less than `max_incoming`.

When sending GRANTs, Homa uses the highest unscheduled priority level
for the highest priority active message, the next highest priority
level for the next message, and so on. If the number of messages
being granted to exceeds the available priority levels, then multiple
messages will share the lowest priority level.

## Sender-side SRPT and pacing
If a sender has multiple messages ready to transmit (i.e. each
message has packets that have been granted or are unscheduled), then
it must prioritize the messages based on the total number of bytes
each message has left to transmit.
At any given time, the sender must transmit only packets from
the highest priority message.  Once all transmittable packets
from that message been sent, then the sender can proceed to the next
highest priority message, and so on.

In order for this mechanism to work properly, senders must limit the
amount of packet queuing in the NIC. For example, if a
sender "sends" several packets from a long message in rapid succession,
most of the packets will be queued in the NIC.
If a message with a single packet now becomes ready to transmit,
its packet will be queued behind those from the longer message,
which violates SRPT.

To prevent this problem, Homa employs a *pacer* mechanism. Homa
maintains a running estimate of how many bytes have been passed to the
NIC but not yet transmitted (the *NIC backlog*). If this exceeds a
threshold value (specified in units of time with the `max_nic_queue_ns`
parameter) then no more packets will be transmitted until the
NIC backlog drops below the limit. Homa maintains a *throttled list*,
which contains outgoing messages that have packets ready to transmit.
A dedicated pacer thread monitors the NIC backlog and transmits
packets from the throttled list in SRPT order.

Unfortunately, there are conditions under which a single pacer
thread cannot keep up with outgoing traffic (such as when there
are many short messages). As a result, the pacer mechanism
contains several embellishments, such as bypassing the throttled list
for very short messages, and enlisting other threads to help
transmit packets if the pacer gets behind.
See the code (mostly in `homa_outgoing.c`) for details of these mechanisms.

## FIFO packet scheduling
Homa's SRPT priority mechanism can potentially result in starvation: if
the network is persistently overloaded, a very long message might never be
transmitted. To mitigate this problem, Homa dedicates a small fraction of
its network bandwidth to the *oldest* message instead of the highest
priority message. This technique is used both in the grant mechanism
(for determining which messages to grant) and in the pacer mechanism
(for determining which message to transmit). It is controlled by
two parameters: `grant_fifo_fraction` and `pacer_fifo_fraction`.
In practice, the risk of starvation appears to be very low, even without
the FIFO mechanism.