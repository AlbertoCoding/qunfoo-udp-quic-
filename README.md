# Protocols, QUNFOO over UDP and QUIC, Wireshark dissector
![Python 3](https://img.shields.io/badge/Language-Python%203-red) ![Language C](https://img.shields.io/badge/Language-C-yellow) ![Tool Wireshark](https://img.shields.io/badge/Tool-Wireshark-blue)

This is the repository with the programs developed


## Details / Requirements:

This is the repository with the programs developed:
* QUNFOO chat over UDP (client + server)
* QUNFOO chat over QUIC (client)
* QUNFOO chat over QUIC (server)
* Wireshark dissector for QUNFOO


# USAGE
-------
## QUNFOO chat over UDP
### Server
```
python3 chat.py
```
### Client
```
python3 chat.py <SERVER_IP>
python3 chat.py 127.0.0.1
```
### Commands to execute on the client:
```
<MESSAGE>                       -->    Send a general message to everyone
.list                           -->    List all the users in the chat: 
.priv <DST_USERNAME> <MESSAGE>  -->    Send a private message to a user: $ .priv <Dst_Nick> <Message>
.nick <OLD_NICK> <NEW_NICK>     -->    Change the nickname of a user
.quit                           -->    Exit the chat
.help                           -->    See the help manual
```
-------

## QUNFOO chat over QUIC

### Server
```
python3 http3_server5.0.py --certificate <CERTIFICATE> --private-key <PRIVATE_KEY>
python3 http3_server5.0.py --certificate ssl_cert.pem --private-key ssl_key.pem
```
### Client
```
python3 siduck_client5.0.py <SERVER_IP> <SERVER_PORT> -k
python3 siduck_client5.0.py 127.0.0.1 4433 -k
```
### Commands to execute on the client:
```
<MESSAGE>                       -->    Send a general message to everyone
.list                           -->    List all the users in the chat: 
.priv <DST_USERNAME> <MESSAGE>  -->    Send a private message to a user: $ .priv <Dst_Nick> <Message>
.nick <OLD_NICK> <NEW_NICK>     -->    Change the nickname of a user
.quit                           -->    Exit the chat
.help                           -->    See the help manual
```
-------

## Some references to websites that made this tool possible (code help, ideas, etc):

* https://github.com/aiortc/aioquic
* More pending to be added


Author: Alberto
