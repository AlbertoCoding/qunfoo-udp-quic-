import argparse
import asyncio
import importlib
import logging
import time
from collections import deque
from email.utils import formatdate
from typing import Callable, Deque, Dict, List, Optional, Union, cast

import wsproto
import wsproto.events
from quic_logger import QuicDirectoryLogger

import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.h3.exceptions import NoAvailablePushIDError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived, ProtocolNegotiated, QuicEvent, HandshakeCompleted, StreamDataReceived, ConnectionIdIssued
from aioquic.tls import SessionTicket

from aioquic.quic.connection import QuicConnection

try:
    import uvloop
except ImportError:
    uvloop = None

AsgiApplication = Callable
HttpConnection = Union[H0Connection, H3Connection]

SERVER_NAME = "aioquic/" + aioquic.__version__

global usuarios
usuarios = {}


def packetByeBuilt(packet):
    packet["packetType"] = chr(2)

    return pck2str(packet)


def packetMessageBuilt(packet, nick, message):

    packet["packetType"] = chr(3)
    packet["nickSrcSize"] = chr(len(nick))
    packet["nickSrc"] = nick
    packet["messageSize"] = chr(len(message))
    packet["message"] = message

    return pck2str(packet)


def packetPrivateBuilt(packet, nickSrc, nickDst, message):

    packet["packetType"] = chr(4)
    packet["nickSrcSize"] = chr(len(nickSrc))
    packet["nickSrc"] = nickSrc
    packet["nickDstSize"] = chr(len(nickDst))
    packet["nickDst"] = nickDst
    packet["messageSize"] = chr(len(message))
    packet["message"] = message

    return pck2str(packet)


def packetACK_ListBuilt(packet, message):
    packet["packetType"] = chr(14)
    packet["messageSize"] = chr(len(message))
    packet["message"] = message

    return pck2str(packet)


def processHello(data, offset):

    nickSrcSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickSrcSize
    nickSrc = data.decode()[offset:end]
    offset = offset + nickSrcSize

    if not nickSrc in usuarios.keys():
        print("LOG: New user be added: " + nickSrc)
        usuarios[nickSrc] = ""


def processQuit(data, offset):

    nickSrcSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickSrcSize
    nickSrc = data.decode()[offset:end]
    offset = offset + nickSrcSize

    usuarios.pop(nickSrc)


def processNick(data, offset):
    nickSrcSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickSrcSize
    nickSrc = data.decode()[offset:end]
    offset = offset + nickSrcSize

    nickDstSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickDstSize
    nickDst = data.decode()[offset:end]
    offset = offset + nickDstSize

    roomSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + roomSize
    room = data.decode()[offset:end]
    offset = offset + roomSize

    messageSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + messageSize
    message = data.decode()[offset:end]
    offset = offset + messageSize

    return (nickSrc, nickDst)


def processMsg(data, offset):

    nickSrcSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickSrcSize
    nickSrc = data.decode()[offset:end]
    offset = offset + nickSrcSize

    nickDstSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickDstSize
    nickDst = data.decode()[offset:end]
    offset = offset + nickDstSize

    roomSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + roomSize
    room = data.decode()[offset:end]
    offset = offset + roomSize

    messageSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + messageSize
    message = data.decode()[offset:end]
    offset = offset + messageSize

#    print("[" + nickSrc + "]" + " MESSAGE: " + message)
    return (nickSrc, message)


def processPriv(data, offset):

    nickSrcSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickSrcSize
    nickSrc = data.decode()[offset:end]
    offset = offset + nickSrcSize

    nickDstSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickDstSize
    nickDst = data.decode()[offset:end]
    offset = offset + nickDstSize

    roomSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + roomSize
    room = data.decode()[offset:end]
    offset = offset + roomSize

    messageSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + messageSize
    message = data.decode()[offset:end]
    offset = offset + messageSize

    return (nickSrc, nickDst, message)


def pck2str(packet):
    pckStr = ""
    for i in packet:
        pckStr = pckStr + str(packet[i])

    return pckStr


def userAdded(user):
    isAdded = False
    for key in usuarios.keys():
        if key == user:
            isAdded = True

    return isAdded


def userListStr():
    userList = ""
    for key in usuarios.keys():
        userList = userList + str(key)  + " "

    return userList


def getPacketName(packet_types, num):

    return packet_types[num]


class HttpServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._handlers: Dict[int, Handler] = {}
        self._http: Optional[HttpConnection] = None
        self.var = ""


    def userAdded(user):
        isAdded = False
        for key in usuarios.keys():
            if key == user:
                isAdded = True

        return isAdded


    def userListStr():
        userList = ""
        for key in usuarios.keys():
            userList = userList + str(key)  + " "

        return userList


    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            print("LOG: Handshake Completed")
             #        print("segunda parte")
           #   con = QuicConnection(configuration)
          #  con.change_connection_id()
          #  print(str(con.connection_id))
#
 #           print(str(self._quic.original_destination_connection_id))
   #         usuarios.append(self._quic)

        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol.startswith("h3-"):
                self._http = H3Connection(self._quic)
            elif event.alpn_protocol.startswith("hq-"):
                self._http = H0Connection(self._quic)

        elif isinstance(event, DatagramFrameReceived):

            packet_types = [ "NULL", "HELLO", "BYE", "MSG", "PRIV",
                             "NICK", "LIST", "QUIT", "ROOM",
                             "ACK_HELLO", "ACK_BYE", "ACK_MSG", "ACK_PRIV",
                             "ACK_NICK", "ACK_LIST", "ACK_QUIT", "ACK_ROOM" ]

            defaultVal = "-"
            defaultSize = chr(1)

            packet = {
                "packetType": 0,
                "nickSrcSize": defaultSize,
                "nickSrc": defaultVal,
                "nickDstSize": defaultSize,
                "nickDst": defaultVal,
                "roomSize": defaultSize,
                "room": defaultVal,
                "messageSize": defaultSize,
                "message": defaultVal
            }

            offset = 0
            end = 0

            data = event.data.decode("utf-8")
            packet_list = event.data.decode("utf-8").split("@")

            packetType_num = ord(data[0])
#            packetType = getPacketName(packet_types, packetType_num)
            offset = offset + 1

            if packetType_num == 1: #HELLO
                processHello(event.data, offset)

            elif packetType_num == 6: #LIST
                ackList_pck = packet
                ackList_pck_str = packetACK_ListBuilt(ackList_pck, userListStr())
                self._quic.send_datagram_frame(ackList_pck_str.encode())
                print("LOG: Userlist sent")

            elif packetType_num == 7: #QUIT
                processQuit(event.data, offset)

                bye_pck = packet
                bye_pck_str = packetByeBuilt(bye_pck)
                self._quic.send_datagram_frame(bye_pck_str.encode())

                print("Borrar usuario de USERLIST")

            elif  packetType_num == 5: #NICK
                oldNick, newNick = processNick(event.data, offset)
                usuarios.pop(oldNick)
                usuarios[newNick] = ""
                print("LOG: username " + oldNick  +  " changed to username " +  newNick )

            elif packetType_num == 3: #MSG
                nickSrc, message = processMsg(event.data, offset)
                print("LOG: Message from " + nickSrc  + " to all -> " + message)

                message_pck = packet
                message_pck_str = packetMessageBuilt(message_pck, nickSrc, message)
                for key in usuarios.keys():
                     usuarios[key] = message_pck_str

            elif packetType_num == 4: #PRIV
                nickSrc, nickDst, message = processPriv(event.data, offset)
                print("LOG: [" + nickSrc + "] sends PRIV to " + nickDst + ": " + message)

                priv_pck = packet
                priv_pck_str = packetPrivateBuilt(packet, nickSrc, nickDst, message)

                if nickDst in usuarios.keys():
                    usuarios[nickDst] = priv_pck_str


            elif event.data == b"quack":
                print("LOG: Quack-recibido")
                self._quic.send_datagram_frame(b"quack-ack")
                print("LOG: Quack-ack enviado")

            elif event.data.decode("utf-8").split()[0] == "BEACON":
                user = event.data.decode("utf-8").split()[1]
                self.var = ""
                if user in usuarios:
                    if usuarios[user] != "":
                        message_pck_str = usuarios[user]
                        self._quic.send_datagram_frame(message_pck_str.encode())
                        usuarios[user] = ""
                    else:
                        self._quic.send_datagram_frame(b"BEACON ACK")
                else:
                    print("Unrecognized user: " + str(user))
                    self._quic.send_datagram_frame(b"BEACON ACK")


            elif packet_list[0] == "MSG":
                usuarios[packet_list[2]] = packet_list[3] + "@"+ packet_list[1]
                self._quic.send_datagram_frame(b"MSG ACK")

            else:
#                print("LOG: " + event.data.decode("utf-8")  + " recibido")
                self._quic.send_datagram_frame(b"ququ")
                print("Ququ enviado: REVIEW CODE")

        elif isinstance(event, StreamDataReceived):
            print("LOG: Stream data: " + str(event.stream_id) + " " + event.data.decode("utf-8") + "recibido")
            print("Connection ID_stream" + str(self._quic.original_destination_connection_id))



class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self) -> None:
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, ticket: SessionTicket) -> None:
        self.tickets[ticket.ticket] = ticket

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC server")
    parser.add_argument(
        "app",
        type=str,
        nargs="?",
        default="demo:app",
        help="the ASGI application as <module>:<attribute>",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        required=True,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4433,
        help="listen on the specified port (defaults to 4433)",
    )
    parser.add_argument(
        "-k",
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="send a retry for new connections",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # import ASGI application
    module_str, attr_str = args.app.split(":", maxsplit=1)
    module = importlib.import_module(module_str)
    application = getattr(module, attr_str)

    # create QUIC logger
    if args.quic_log:
        quic_logger = QuicDirectoryLogger(args.quic_log)
    else:
        quic_logger = None

    # open SSL log file
    if args.secrets_log:
        secrets_log_file = open(args.secrets_log, "a")
    else:
        secrets_log_file = None

    configuration = QuicConfiguration(
        alpn_protocols=H3_ALPN + H0_ALPN + ["qunfoo"],
        is_client=False,
        max_datagram_frame_size=65536,
        quic_logger=quic_logger,
        secrets_log_file=secrets_log_file,
    )

    # load SSL certificate and key
    configuration.load_cert_chain(args.certificate, args.private_key)

    ticket_store = SessionTicketStore()

    if uvloop is not None:
        uvloop.install()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        serve(
            args.host,
            args.port,
            configuration=configuration,
            create_protocol=HttpServerProtocol,
            session_ticket_fetcher=ticket_store.pop,
            session_ticket_handler=ticket_store.add,
            retry=args.retry,
        )
    )
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
