import time
import argparse
import asyncio
import logging
import ssl

import sys
import select
import random
import threading

from typing import Optional, cast

from quic_logger import QuicDirectoryLogger

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived, QuicEvent, ConnectionIdIssued

from aioquic.quic.connection import QuicConnection

logger = logging.getLogger("client")





class SiduckClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[None]] = None

    async def quack(self) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."
        self._quic.send_datagram_frame(b"quack")
        print("LOG: Quack enviado")

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)


    async def quack2(self) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."
        self._quic.send_datagram_frame(b"Mensaje1")
        print("LOG: mensaje enviado")

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)


    async def free(self, msg) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."
        self._quic.send_datagram_frame(str(msg).encode())
        print("LOG: " + str(msg)  + " enviado")

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)


    async def beacon(self, nick) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."
        beac = "BEACON " + str(nick)
#        beac = "BEACON"
        self._quic.send_datagram_frame(str(beac).encode())
        #print("BEACON: " + str(beac) + " enviado")

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)


    async def qunfoo(self, msg, user, nick) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."

        data = "MSG" + "@" + msg + "@" + user + "@" + nick
        self._quic.send_datagram_frame(str(data).encode())
        print("LOG: " + str(data)  + " enviado")

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)


    def priv(self, private_pck_str) -> None:
        self._quic.send_datagram_frame(private_pck_str.encode())



    def hello(self, hello_pck_str) -> None:

        self._quic.send_datagram_frame(hello_pck_str.encode())



    async def list(self, list_pck_str) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."

        self._quic.send_datagram_frame(list_pck_str.encode())
#        print("LOG: " +  "Userlist requested")
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)


    async def quit(self, quit_pck_str) -> None:
        assert self._ack_waiter is None, "Only one quack at a time."

        self._quic.send_datagram_frame(quit_pck_str.encode())

        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)


    def nick(self, nick_pck_str) -> None:
        self._quic.send_datagram_frame(nick_pck_str.encode())

    def msg(self, message_pck_str) -> None:
        self._quic.send_datagram_frame(message_pck_str.encode())


    def quic_event_received(self, event: QuicEvent) -> None:

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


        if self._ack_waiter is not None:
            if isinstance(event, DatagramFrameReceived) and event.data == b"quack-ack":
                print("LOG: Quack-ack recibido")

                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(None)

                self._quic.send_stream_data(
                    stream_id=self._quic.get_next_available_stream_id(),
                    data=bytes("Gracias por el ack".encode()),
                    end_stream=False,
                )
                self.transmit()

                time.sleep(2)

                self._quic.send_stream_data(
                    stream_id=self._quic.get_next_available_stream_id(),
                    data=bytes("Gracias por el ack2".encode()),
                    end_stream=False,
                )
                self.transmit()

            elif isinstance(event, DatagramFrameReceived) and event.data == b"ququ":
                print("LOG: Ququ recibido : " + event.data.decode("utf-8"))

                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(None)

            elif isinstance(event, DatagramFrameReceived) and event.data == b"BEACON ACK":
                #print("LOG: BEACON ACK received")

                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(None)

            elif isinstance(event, DatagramFrameReceived):

                offset = 0
                end = 0
                packetType_num = 0

                data = event.data.decode("utf-8")
                if data != "":
                    packetType_num = ord(data[0])
                    offset = offset + 1

                if packetType_num == 2: #BYE
                    print("Bye bye")

                elif packetType_num == 3: #MSG
                    processMsg(event.data, offset)

                elif packetType_num == 4: #PRIV
                    nickSrc, nickDst, message = processPriv(event.data, offset)
                    print("[" + nickSrc + "]" + " PRIV: " + message)

                elif packetType_num == 14: #ACK_LIST
                    processACK_List(event.data, offset)

                else:
                    print(event.data.decode("utf-8"))

                waiter = self._ack_waiter
                self._ack_waiter = None
                waiter.set_result(None)


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

    print("[" + nickSrc + "]" + " MESSAGE: " + message)

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



def packetHelloBuilt(packet, nick):

    packet["packetType"] = chr(1)
    packet["nickSrcSize"] = chr(len(nick))
    packet["nickSrc"] = nick

    return pck2str(packet)


def processACK_List(data, offset):

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

    message_list = message.split("\n")
    print("#CHAT'S USERLIST#")
    print(message)


def packetQuitBuilt(packet, nickSrc):

    packet["packetType"] = chr(7)
    packet["nickSrcSize"] = chr(len(nickSrc))
    packet["nickSrc"] = nickSrc

    return pck2str(packet)


def pck2str(packet):
    pckStr = ""
    for i in packet:
        pckStr = pckStr + str(packet[i])

    return pckStr


def packetListBuilt(packet):

    packet["packetType"] = chr(6)

    return pck2str(packet)


def packetNickBuilt(packet, nickSrc, nickDst):

    packet["packetType"] = chr(5)
    packet["nickSrcSize"] = chr(len(nickSrc))
    packet["nickSrc"] = nickSrc
    packet["nickDstSize"] = chr(len(nickDst))
    packet["nickDst"] = nickDst

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


def packetCleaner(packet):

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

    return packet



async def run(configuration: QuicConfiguration, host: str, port: int) -> None:
    async with connect(
        host, port, configuration=configuration, create_protocol=SiduckClient
    ) as client:

        client = cast(SiduckClient, client)

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


        nick = "User" + str(random.randint(0,1000))
        print("Hola " + nick)

        hello_pck = packet
        hello_pck_str = packetHelloBuilt(hello_pck, nick)
        client.hello(hello_pck_str)
#        beaconQunfoo = threading.Thread(target = beaconHandler, args=(client, nick), daemon=True)
#        beaconQunfoo.start()

        var = True
        while True:
            if var:
                print("$", end=" ", flush=True)
            var = True

            i, o, e = select.select([sys.stdin], [], [], 1)
            if(i):
                raw = sys.stdin.readline().strip()
#                print("You said " + raw)
                raw_list = raw.split()
            else:
#                print("You said nothing in the last 15 seconds!")
#                logger.info("Sending BEACON")
                await client.beacon(nick)
                var = False
                continue

            packet = packetCleaner(packet)

            if raw == "":
                True
            elif raw_list[0] == ".quit":

                quit_pck = packet
                quit_pck_str = packetQuitBuilt(quit_pck, nick)
                await client.quit(quit_pck_str)

                break

            elif raw_list[0] == ".list":
                list_pck = packet
                list_pck_str = packetListBuilt(list_pck)
                await client.list(list_pck_str)

            elif raw_list[0] == ".priv":
                nickSrc = nick
                nickDst = raw_list[1]
                msg = ""
                for i in raw_list[2:]:
                    msg = msg + ' ' + i

                private_pck = packet
                private_pck_str = packetPrivateBuilt(private_pck, nickSrc, nickDst, msg)
                client.priv(private_pck_str)

            elif raw_list[0] == ".priv2":
                userTo = raw_list[1]
                msg = raw_list[2]
                await client.qunfoo(msg, userTo, nick)

            elif raw_list[0] == ".nick":
                oldNick = raw_list[1]
                newNick = raw_list[2]

                nick_pck = packet
                nick_pck_str = packetNickBuilt(nick_pck, oldNick, newNick)
                client.nick(nick_pck_str)
                print("Your new nick is: " + newNick)
                nick = newNick

            elif raw_list[0] == ".beacon":
                logger.info("Sending BEACON")
                await client.beacon(nick)

            elif raw_list[0] == ".free":
                logger.info("Sending free message")
                await client.free(raw_list[1])

            elif raw_list[0] == ".time":
                print("You have 5 seconds to answer")
                i, o, e = select.select([sys.stdin], [], [], 5)
                if(i):
                    print("You said " + sys.stdin.readline().strip())
                else:
                    print("You said nothing!")
            elif raw_list[0] == ".py":
                logger.info("sending quack")
                await client.quack()
                logger.info("received quack-ack")
                await client.quack2()
                logger.info("enviado quack2")

            elif raw_list[0] == ".help":
                print(" What you can do with the chat: ")
                print("a) Directly write your message (it will be sent to all): $ <Message>")
                print("b) List all the users in the chat: $ .list")
                print("c) Exit the chat: $ .quit")
                print("d) See the manual help: $ .help")
                print("e) Send a general message to everyone: $ <Message>")
                print("f) Send a private message to a user: $ .priv <Dst_Nick> <Message>")
                print("g) Change the nickname of a user: $ .nick <Old_Nick> <New_Nick>")

            else:
                message_pck = packet
                message_pck_str = packetMessageBuilt(message_pck, nick, raw)
                client.msg(message_pck_str)


        sys.exit(0)


#        print("segunda parte")
#        con = QuicConnection(configuration)
#        con.change_connection_id()
#        print(str(con.connection_id))




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SiDUCK client")
    parser.add_argument(
        "host", type=str, help="The remote peer's host name or IP address"
    )
    parser.add_argument("port", type=int, help="The remote peer's port number")
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    configuration = QuicConfiguration(
        alpn_protocols=["qunfoo"], is_client=True, max_datagram_frame_size=65536
    )
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.quic_log:
        configuration.quic_logger = QuicDirectoryLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        run(configuration=configuration, host=args.host, port=args.port)
    )
