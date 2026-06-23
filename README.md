ID-INT Debug/Traceroute Tool
============================

This tool sends an empty UDP packet with an ID-INT header from a client to a server. The server
responds with a UDP packet containing a fresh ID-INT header and the original ID-INT header from the
client as payload.

Use with this [fork of SCION](https://github.com/lschulz/scion/tree/idint2026).

To build just run `go build`.

## Usage
Run the server in one AS
```bash
./idint-traceroute --sciond [fd00:f00d:cafe::7f00:54]:30255 --local [fd00:f00d:cafe::7f00:53]:32001
```

and the client in another
```bash
./idint-traceroute -sciond 127.0.0.60:30255 -local 127.0.0.1:32000 \
  -remote 2-ff00:0:222,[fd00:f00d:cafe::7f00:53]:32001 -encrypt \
  -nid -inst0 RTT_NEXT_BR --inst1 EGRESS_LINK_TX -inst2 INGRESS_TSTAMP -inst3 INST_QUEUE_LEN
```

If idint-traceroute can't key keys, make sure the `local` address in the command above matches
the address the SCION daemon (which idint-traceroute uses) responsible for the AS you want to run
id-int-traceroute in.

If the border routes can't get level 1 keys, make sure their IPs are allows for `idint` keys in the
`drkey.delegation` section of the control service configuration.

To select the path and run continuously use the `-i` (interactive) switch. Also see
`./idint-traceroute -h`.

Example output:
```
Forward:
  Flags      Source AS NodeID     RttNextBr  EgressLinkTx IngressTstamp  InstQueueLen
 S ---C   1-ff00:0:112      -             -             -             -             -
 0 -E-C   1-ff00:0:112      2         0.243         7.84%  c381a0fe2c0d             0
 1 I--C   1-ff00:0:111      2         0.344         0.09%  c381a1020876             0
 1 -E-C   1-ff00:0:111      1         0.258         0.01%  c381a111faf0             0
 2 IE-C   2-ff00:0:211      1         0.211         0.22%  c381a11446f3             0
 3 I--C   2-ff00:0:222      1             -         0.22%  c381a116e7b2             0

Reverse:
  Flags      Source AS NodeID     RttNextBr  EgressLinkTx IngressTstamp  InstQueueLen
 S ---C   2-ff00:0:222      -             -         0.00%  c381a11a6007             -
 0 -E-C   2-ff00:0:222      1         0.272         0.00%  c381a11b87bb             0
 1 IE-C   2-ff00:0:211      1         0.300         0.02%  c381a11db835             0
 2 I--C   1-ff00:0:111      1         0.290         0.06%  c381a1200a6f             0
 2 -E-C   1-ff00:0:111      2         0.321         0.24%  c381a121acf5             0
 3 I--C   1-ff00:0:112      2             -         0.00%  c381a1251ed7             0
```
