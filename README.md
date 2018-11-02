# neo-wireshark-plugin
a neo p2p protocol lua plugin for wireshark
# install
## ubuntu 
*  install wireshark 
reference: 
https://osqa-ask.wireshark.org/questions/16343/install-wireshark-on-ubuntu
https://askubuntu.com/questions/700712/how-to-install-wireshark
* edit /usr/share/wireshark/init.lua, append this:
```
dofile("${YourDirectory}/neo-wireshark-plugin/neo.lua")
```
* open wireshark and filter *neo*

## windows
* install wireshark
* copy *neo.lua* to your wireshark installation directory
* edit *init.lua*,  change
```
disable_lua = false
```
and add this:
```
dofile("neo.lua")
```
# todo
v1.0.0: when bytes splited into packets got the assertion: 
```
Dissector bug, protocol TCP: /build/wireshark-rjGTDh/wireshark-2.6.3/epan/dissectors/packet-tcp.c:5591: failed assertion "save_desegment_offset == pinfo->desegment_offset && save_desegment_len == pinfo->desegment_len"
```
v1.1.0: still something wrong with *headers*




