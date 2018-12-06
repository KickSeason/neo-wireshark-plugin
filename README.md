# neo-wireshark-plugin
a wireshark lua plugin for neo p2p protocol
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




