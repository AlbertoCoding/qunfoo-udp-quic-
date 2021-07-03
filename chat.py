import socket
import sys
import random
import threading
import time


def getPacketNum(packet_types, pck):
    result = -1

    for i in range(len(packet_types)-1):
        if packet_types[i] == pck:
            result = i

    return result


def getPacketName(packet_types, num):

    return packet_types[num]


def pck2str(packet):
    pckStr = ""
    for i in packet:
        pckStr = pckStr + str(packet[i])

    return pckStr


def initialConnection(connect_pck, server):
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSock.sendto(connect_pck.encode(), server)

    return clientSock


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
    #i = 0
    #while i < len(message_list):
    #    print(message_list[i], end="\n")
    #    i += 1



def processMsg(data, addr, offset):

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


def serverHandler(sck):
    packet_types = [ "NULL", "HELLO", "BYE", "MSG", "PRIV",
                    "NICK", "LIST", "QUIT", "ROOM",
                    "ACK_HELLO", "ACK_BYE", "ACK_MSG", "ACK_PRIV",
                    "ACK_NICK", "ACK_LIST", "ACK_QUIT", "ACK_ROOM" ]

    while True:
        data, addr = sck.recvfrom(1024)

        offset = 0
        end = 0

        packetType_num = ord(data.decode()[offset])
        packetType = getPacketName(packet_types, packetType_num)
        offset = offset + 1

        if packetType == "BYE":
            print("GOODBYE!")
            break

        elif packetType == "MSG":
            processMsg(data, addr, offset)

        elif packetType == "PRIV":
            nickSrc, nickDst, message = processPriv(data, addr, offset)
            print("[" + nickSrc + "]" + " PRIV: " + message)

        elif packetType == "ACK_LIST":
            processACK_List(data, offset)

        else:
            print(data.decode()[0])



def packetHelloBuilt(packet, nick):

    packet["packetType"] = chr(1)
    packet["nickSrcSize"] = chr(len(nick))
    packet["nickSrc"] = nick

    return pck2str(packet)


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


def packetNickBuilt(packet, nickSrc, nickDst):

    packet["packetType"] = chr(5)
    packet["nickSrcSize"] = chr(len(nickSrc))
    packet["nickSrc"] = nickSrc
    packet["nickDstSize"] = chr(len(nickDst))
    packet["nickDst"] = nickDst

    return pck2str(packet)


def packetListBuilt(packet):

    packet["packetType"] = chr(6)

    return pck2str(packet)


def packetQuitBuilt(packet, nickSrc):

    packet["packetType"] = chr(7)
    packet["nickSrcSize"] = chr(len(nickSrc))
    packet["nickSrc"] = nickSrc

    return pck2str(packet)


def packetRoomBuilt(packet, nickSrc, room):

    packet["packetType"] = chr(8)
    packet["nickSrcSize"] = chr(len(nickSrc))
    packet["nickSrc"] = nickSrc
    packet["roomSize"] = chr(len(room))
    packet["room"] = room

    return pck2str(packet)


def packetACK_ListBuilt(packet, message):
    packet["packetType"] = chr(14)
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


def clientChat(server_ip):

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

    UDP_IP_ADDRESS = str(server_ip)
    UDP_PORT_NO = 1234
    server = (UDP_IP_ADDRESS, UDP_PORT_NO)
    nick = "User" + str(random.randint(0,1000))
    print("Hola: " + nick)

    hello_pck = packet
    hello_pck_str = packetHelloBuilt(hello_pck, nick)

    sck = initialConnection(hello_pck_str, server)
    data, addr = sck.recvfrom(1024)
    print(data.decode())


    serverPackets = threading.Thread(target=serverHandler, args=(sck,), daemon=True)
    serverPackets.start()

    while True:

        packet = packetCleaner(packet)

        time.sleep(0.01)
        print("$ ", end = "")
        raw = input()
        raw_list = raw.split()

        if raw_list[0] == ".quit":
            quit_pck = packet
            quit_pck_str = packetQuitBuilt(quit_pck, nick)
            sck.sendto(quit_pck_str.encode(), server)

            break

        elif raw_list[0] == ".list":
            list_pck = packet
            list_pck_str = packetListBuilt(list_pck)
            sck.sendto(list_pck_str.encode(), server)

        elif raw_list[0] == ".nick":
            oldNick = raw_list[1]
            newNick = raw_list[2]

            nick_pck = packet
            nick_pck_str = packetNickBuilt(nick_pck, oldNick, newNick)
            sck.sendto(nick_pck_str.encode(), (UDP_IP_ADDRESS, UDP_PORT_NO))
            nick = newNick

        elif raw_list[0] == ".priv":
            nickSrc = nick
            nickDst = raw_list[1]
            msg = ""
            for i in raw_list[2:]:
                msg = msg + ' ' + i

            private_pck = packet
            private_pck_str = packetPrivateBuilt(private_pck, nickSrc, nickDst, msg)
            sck.sendto(private_pck_str.encode(), (UDP_IP_ADDRESS, UDP_PORT_NO))

        elif raw_list[0] == ".room":
            room = raw_list[1]
            room_pck = packet
            room_pck_str = packetRoomBuilt(room_pck, nick, room)
            sck.sendto(room_pck_str.encode(), (UDP_IP_ADDRESS, UDP_PORT_NO))

        elif raw_list[0] == ".help":
            print(" What you can do with the chat: ")
            print("a) Directly write your message (it will be sent to all): $ <Message>")
            print("b) List all the users in the chat: $ .list")
            print("c) Exit the chat: $ .quit")
            print("d) See the manual help: $ .help")
            print("e) Send a general message to everyone: $ <Message")
            print("f) Send a private message to a user: $ .priv <Dst_Nick> <Message>")
            print("g) Change the nickname of a user: $ .nick <Old_Nick> <New_Nick>")


        else: # For normal messages
            message_pck = packet
            message_pck_str = packetMessageBuilt(message_pck, nick, raw)
            sck.sendto(message_pck_str.encode(), (UDP_IP_ADDRESS, UDP_PORT_NO))


    serverPackets.join()

    sck.close()



def changeNick(oldNick, newNick, userlist):

    tmp_userValue = userlist[oldNick]
    userlist[newNick] = tmp_userValue
    userlist.pop(oldNick)

    return True


def processHello(data, addr, userlist, offset):

    nickSrcSize = ord(data.decode()[offset])
    offset = offset + 1

    end = offset + nickSrcSize
    nickSrc = data.decode()[offset:end]
    offset = offset + nickSrcSize

    if not addr in userlist.values():
        print("A new user must be added")
        userlist[nickSrc] = addr


def processPriv(data, addr, offset):

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



def processNick(data, addr, offset):
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


def processQuit(data, addr, userlist, offset):
    j=-1

    for i in userlist:
        if userlist[i] == addr:
            j = i

    if j != -1:
        userlist.pop(j)


def userListStr(userlist):
    userlist_str = ""

    for i in userlist:
        userlist_str = userlist_str + i  + " : " + userlist[i][0] + ", " + str(userlist[i][1])  + "\n" 

    return userlist_str



def processRoom(data, addr, offset):
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

    return (nickSrc, room)



def processData(data, addr, sck, userlist, roomlist):

    packet_types = [ "NULL", "HELLO", "BYE", "MSG", "PRIV",
                    "NICK", "LIST", "QUIT", "ROOM",
                    "ACK_HELLO", "ACK_BYE", "ACK_MSG", "ACK_PRIV",
                    "ACK_NICK", "ACK_LIST", "ACK_QUIT", "ACK_ROOM", ]

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

    packetType_num = ord(data.decode()[offset])
    packetType = getPacketName(packet_types, packetType_num)
    offset = offset + 1

    if packetType == "HELLO":
        processHello(data, addr, userlist, offset)
        msgFromServer = "Welcome to the chat" + "!"
        sck.sendto(msgFromServer.encode(), addr)

    elif packetType == "MSG":
        nickSrc, message = processMsg(data, addr, offset)

        message_pck = packet
        message_pck_str = packetMessageBuilt(message_pck, nickSrc, message)

        for i in userlist:
            sck.sendto(message_pck_str.encode(), userlist[i])

    elif packetType == "PRIV":
        nickSrc, nickDst, message = processPriv(data, addr, offset)
        print("[" + nickSrc + "]" + " PRIV: " + message)

        addrDst = userlist[nickDst]
        priv_pck = packet
        priv_pck_str = packetPrivateBuilt(packet, nickSrc, nickDst, message)
        sck.sendto(priv_pck_str.encode(), addrDst)

    elif packetType == "NICK":
        oldNick, newNick = processNick(data, addr, offset)
        changeNick(oldNick, newNick, userlist)

    elif packetType == "LIST":
        userlist_str = userListStr(userlist)
        print(userlist_str)
        ackList_pck = packet
        ackList_pck_str = packetACK_ListBuilt(ackList_pck, userlist_str)
        sck.sendto(ackList_pck_str.encode(), addr)

    elif packetType == "QUIT":
        processQuit(data, addr, userlist, offset)

        bye_pck = packet
        bye_pck_str = packetByeBuilt(bye_pck)
        sck.sendto(bye_pck_str.encode(), addr)

    elif packetType == "ROOM":
        nickSrc, room = processRoom(data, addr, offset)
        roomlist[room] = []
        roomlist[room].append(nickSrc)
 
        for i in range(len(roomlist[room])):
            elem = roomlist[room][i]
            if elem:
                print(elem)

    else:
        print("THIS IS NOTHING")

    return True


def serverChat():
    ## Here we define the UDP IP address as well as the port number that we have
    ## already defined in the client python script.
    UDP_IP_ADDRESS = "127.0.0.1"
    UDP_PORT_NO = 1234
    server = (UDP_IP_ADDRESS, UDP_PORT_NO)
    userlist = {}
    roomlist = {}

    ## declare our serverSocket upon which
    ## we will be listening for UDP messages
    sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ## One difference is that we will have to bind our declared IP address
    ## and port number to our newly declared serverSock
    sck.bind((UDP_IP_ADDRESS, UDP_PORT_NO))

    while True:
        data, addr = sck.recvfrom(1024)
        processData(data, addr, sck, userlist, roomlist)
        #print(str(addr[0]) + " " + data.decode())


def main():
#pendiente de usar un parseador de argumentos como argparse
    if len(sys.argv)==1:
        serverChat()
    elif len(sys.argv)==2:
        if sys.argv[1]=="-h" or sys.argv[1]=="--help":
            print(" Usage: ")
            print("# Run as server: $ python chat.py")
            print("# Run as client: $ python chat.py <server_ip_address>")
            print("1)Write your message")
            print("2)List all the users in the chat $cmd list")
            print("3)Exit the chat $cmd quit")
            print("")
            print(" What you can do with the chat: ")
            print("a) Directly write your message (it will be sent to all): $ <Message>")
            print("b) List all the users in the chat: $ .list")
            print("c) Exit the chat: $ .quit")
            print("d) See the manual help: $ .help")
            print("e) Send a general message to everyone: $ <Message")
            print("f) Send a private message to a user: $ .priv <Dst_Nick> <Message>")
            print("g) Change the nickname of a user: $ .nick <Old_Nick> <New_Nick>")


        else:
            clientChat(sys.argv[1])


if __name__ == '__main__':
    main()
