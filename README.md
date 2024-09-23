ID-INT Debug/Traceroute Tool
============================

This tool sends an empty UDP packet with an ID-INT header from a client to a server. The server
responds with a UDP packet cotaining a fresh ID-INT header and the original ID-INT header from the
client as payload.

Example output:
```
Source: 127.0.0.1:32000 Dest: 1-ff00:0:112,127.0.0.1:32001
Hops: [1-ff00:0:111 2>2 1-ff00:0:110 3>1 1-ff00:0:112] MTU: 1400 NextHop: 127.0.0.26:31008

Forward:
  Flags      Source AS NodeID        Latency            IPG      RxBitRate IngressLinkRx  InstQueueLen IngressTstamp   IgScifBytes
 S ---C   1-ff00:0:111      -                     999.637ms                            -             -             -             -
 0 -E-C   1-ff00:0:111      2       91.160µs      -58.970µs     54.679Mbps        54.63%             3  aea0deed35be     953021074
 1 IE-C   1-ff00:0:110      1       59.250µs      -32.324µs     54.677Mbps        54.63%             3  aea0deee99d6     953306813
 3 I--C   1-ff00:0:112      1                     -35.649µs     54.680Mbps        54.58%             3  aea0deef8148     956082805

Reverse:
  Flags      Source AS NodeID        Latency            IPG      RxBitRate IngressLinkRx  InstQueueLen IngressTstamp   IgScifBytes
 S ---C   1-ff00:0:112      -      103.369µs      999.583ms                        0.00%             -  aea0def11fa8             -
 0 -E-C   1-ff00:0:112      1      121.630µs        3.636µs     54.677Mbps        54.68%             1  aea0def2b371     952822237
 1 IE-C   1-ff00:0:110      1       59.220µs       30.757µs     54.675Mbps        54.69%             1  aea0def48e8f     953240953
 3 I--C   1-ff00:0:111      2                      10.759µs     54.679Mbps        54.72%             3  aea0def575e3     955966305
```
