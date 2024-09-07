import socket
import struct
import zlib
import math
from threading import Thread, Lock
from time import sleep


def checksum_calculator(data):  # Kalkulator na checksum
    checksum = zlib.crc32(data)
    return checksum


def receive_file(server_socket, fragmentnumber, client_adderss):
    full_packet, sender_address = server_socket.recvfrom(1500)
    # Prijima file od klienta
    udp_header = full_packet[:16]  # Vyberie UDP header
    myhead = full_packet[16:25]  # Vyberie moj header
    data = full_packet[25:]  # Vyberie data

    udp_header = struct.unpack("!IIII", udp_header)  # Rozbali UDP header
    correct_checksum = udp_header[3]
    checksum = checksum_calculator(data)  # Vypocita checksum pre data

    myhead = struct.unpack("!cII", myhead)  # Rozbali moj header
    numberofpacket = myhead[1]
   # print('prisiel packet ', numberofpacket)

    if correct_checksum == checksum:  # Ak sa to zhoduje s headerom
        print('Spravny paket, ', fragmentnumber, ' -posielam fakturu')  # poslem fakturu
        fakture = b'5'  # ze prijaty packet bol spravny
        sprava = struct.pack("!cI", fakture, fragmentnumber)
        server_socket.sendto(sprava, client_adderss)
        fragmentnumber = fragmentnumber - 1

        return data, fragmentnumber


    elif correct_checksum != checksum:  # Ak sa to nezhoduje s hlavickou
        print('Nepravny paket, ', fragmentnumber, ' - posielam ziadost')  # poslem fakturu
        fakture = b'6'  # ze prijaty packet nebol spravny
        sprava = struct.pack("!cI", fakture, fragmentnumber)
        server_socket.sendto(sprava, client_adderss)
        fragmentnumber = fragmentnumber

        return None, fragmentnumber


def receive_message(server_socket, fragmentnumber, client_adderss):
    full_packet, sender_address = server_socket.recvfrom(1500)
    # Prijima spravu od klienta
    udp_header = full_packet[:16]  # Vyberie UDP header
    myhead = full_packet[16:25]  # Vyberie moj header
    data = full_packet[25:]  # Vyberie data

    (i,), data = struct.unpack("I", data[:4]), data[4:]
    dataunpacked, data = data[:i], data[i:]  # Rozbali data

    udp_header = struct.unpack("!IIII", udp_header)
    correct_checksum = udp_header[3]  # Rozbali UDP header

    checksum = checksum_calculator(dataunpacked)  # Vypocita crc32

    if correct_checksum == checksum:  # Ak sa to zhoduje s hlavickou
        print('Spravny paket cislo ', fragmentnumber, ', posielam fakturu')  # poslem fakturu
        fakture = b'5'  # ze prijaty packet bol spravny
        sprava = struct.pack("!cI", fakture, fragmentnumber)
        server_socket.sendto(sprava, client_adderss)

    elif correct_checksum != checksum:  # Ak sa to nezhoduje s hlavickou
        print('Nepravny paket ', fragmentnumber, ', posielam ziadost')  # poslem fakturu
        fakture = b'6'  # ze prijaty packet nebol spravny
        sprava = struct.pack("!cI", fakture, fragmentnumber)
        server_socket.sendto(sprava, client_adderss)

    myhead = struct.unpack("!cII", myhead)
    flag = myhead[0]

    return dataunpacked.decode()


def server(server_socket, client_address):  # Menu pre server
    print("Hi this is menu")
    while True:
        message = ''
        fileend = []
        sprava, sender_address = server_socket.recvfrom(1500)  # Prijima packet od Klienta
        sprava = struct.unpack("!cI", sprava)  # dostaneme spravu s flagom a poctom fragmentov
        flag = sprava[0]
        fragmentsnumber = sprava[1]

        if flag == b'2':  # Flag 2 je na pripravu k spravam
            print('Prijimam message, fragmentov bude ', fragmentsnumber)
            while fragmentsnumber != 0:
                message += receive_message(server_socket, fragmentsnumber, client_address)
                fragmentsnumber = fragmentsnumber - 1
            print("Server prijal mesage \n\n", message)  # Zlozi spravu z paketov a vypise

        if flag == b'3':  # Flag 3 je na pripravu k filu
            print('Prijimam file, fragmentov bude ', fragmentsnumber)
            print("\nZadajte cestu kam chcete ulozit file")  # a sa spyta kam file
            way = input()  # treba ulozit
            while fragmentsnumber != 0:
                fileendhelp, fragmentsnumber = receive_file(server_socket, fragmentsnumber, client_address)
                if fileendhelp == None:
                    continue
                else:
                    fileend += fileendhelp
            fileend = bytearray(fileend)  # Po nacitani spoji pakety
            with open(way, "wb") as file:
                file.write(fileend)

        if flag == b'9':  # Flag 9 je na vymenu roli
            print("Changing roles")
            flag = b'9'  # Posle flag ze je pripraveny
            sprava = struct.pack("!c", flag)
            server_socket.sendto(sprava, client_address)
            server_socket.close()  # Zatvori socket
            client_login()

        if flag == b'6':  # Flag 6 je na opustanie systemu
            print("Bye-Bye")
            flag = b'6'  # Posle flag ze je pripraveny
            sprava = struct.pack("!c", flag)
            server_socket.sendto(sprava, client_address)
            server_socket.close()  # Zatvori socket
            break

        if flag == b'5':  # Flag 5 je na udrziavanie spojenia
            #    print('its ok')
            flag = b'5'
            sprava = struct.pack("!c", flag)
            server_socket.sendto(sprava, client_address)


def server_login():  # Login pre server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Inet - ETHERNET    DGRAM - UDP
    ip = socket.gethostbyname(socket.gethostname())  # Dostanem IP servera do premennej
    print("Zadajte PORT servera")
    port = int(input())  # Zadam svoj port
    server_socket.bind((ip, port))  # Bind

    print('Adresa servera je ', ip)

    while True:
        data, client_address = server_socket.recvfrom(1500)  # Dostane flag a prejde do menu
        if data == b'1':
            server_socket.sendto(b'1', client_address)  # Odosle flag, ze flag je prijaty
            server(server_socket, client_address)  # Prejde do menu ak spojenie je uspesne


##############################################################################################################################################################################################################################################################


def send_file(client_socket, server_address, client_file, packetsize, fragmentsnumber, chyba):
    with open(client_file, mode='rb') as file:
        filestuct = file.read()  # Znovu zakodujem file do potrebnej podoby,
    FILE_SIZE = len(filestuct)  # lebo do funkcie sa ho neda poslat
    packetpomocny = [0] * FILE_SIZE  # Dummy packet
    checksum = checksum_calculator(filestuct)  # Checksum filu
    number_of_packet = fragmentsnumber

    i = 0
    while i <= int(len(packetpomocny)):
        # print(i, i+packetsize)
        # print(filestuct[i:i+packetsize])
        packetDATApart = filestuct[i:i + packetsize]  # Vystrih udajov do paketu
        i = i + packetsize

        source_port = client_socket.getsockname()[1]  # Source port clienta
        destination_port = server_address[1]  # Dest port servera
        data_length = len(packetDATApart)  # Dlzka paketu
        checksumpart = checksum_calculator(packetDATApart)  # Checksum fragmentu
        udp_header = struct.pack("!IIII", source_port, destination_port, data_length, checksumpart)  # Balime header

        flag = b'3'
        myhead = struct.pack("!cII", flag, number_of_packet, checksum)  # Balim moj header

        import random  # Ak chceme chybny packet tak ho
        r = random.uniform(0, 1)  # pokazime s moznostou 90% aby
        if number_of_packet == chyba:  # pri preposielani v buducnosti
            if r < 0.9:  # sme odoslali spravny paket
                packetDATApart = packetDATApart + b'x1'

        packet_with_header = udp_header + myhead + packetDATApart  # Spojenie vsetkeho

        client_socket.sendto(packet_with_header, server_address)  # Odosielanie vsetkeho

        sprava, sender_address = client_socket.recvfrom(1500)  # Dostavame odpoved
        sprava = struct.unpack("!cI", sprava)  # od servera
        fakture = sprava[0]
        fragmentsnumber = sprava[1]

        if fakture == b'5':  # Flag 5 znamena
            if fragmentsnumber == number_of_packet:  # ze server
                print('Fakturu mam od packeta ', number_of_packet)  # dostal spravny
                print(number_of_packet)  # paket
                number_of_packet = number_of_packet - 1

        if fakture == b'6':  # Flag 6 znamena
            print('Nieco sa pokazilo pri pakete ', number_of_packet, ', skusim znovu')  # ze vznikla chyba
            number_of_packet = number_of_packet  # pri odoslani
            #    print(fragmentsnumber)                     # paketu
            #    print(number_of_packet)                    # paket sa odosle
            #    print(i)                                   # znovu
            i = i - packetsize
        #    print(i)

        if number_of_packet == 0:
            print("Sprava uspesne odoslana\n")


def send_message(client_socket, server_address, client_massage, packetsize, fragmentsnumber):
    PACKET_SIZE = len(client_massage)  # Posielanie spravy
    packetpomocny = [0] * PACKET_SIZE  # Dummy packet
    packet = client_massage.encode()  # Sifrovanie spravy
    checksum = checksum_calculator(packet)  # Checksum celeho paketu
    number_of_packet = fragmentsnumber

    for i in range(0, len(packetpomocny), packetsize):
        #  print(i, i+packetsize)
        #  print(client_massage[i:i+packetsize])
        packetDATApart = client_massage[i:i + packetsize].encode()  # Vystrih textu a jeho kodovanie
        source_port = client_socket.getsockname()[1]  # Source port clienta
        destination_port = server_address[1]  # Dest port servera
        data_length = len(packetDATApart)  # Dlzka paketu
        checksumpart = checksum_calculator(packetDATApart)  # Checksum fragmentu
        udp_header = struct.pack("!IIII", source_port, destination_port, data_length, checksumpart)  # Balime header

        packetDATApart = packetDATApart.decode()  # Dekodovanie spravy
        packetDATApart = bytes(packetDATApart, 'utf-8')  # Kodovanie znovu a balenie
        packetDATApartPaked = struct.pack("I%ds" % (len(packetDATApart),), len(packetDATApart), packetDATApart)

        flag = b'2'
        myhead = struct.pack("!cII", flag, number_of_packet, checksum)  # Moj header

        packet_with_header = udp_header + myhead + packetDATApartPaked  # Spojenie vsetkeho

        client_socket.sendto(packet_with_header, server_address)  # Posielanie vsetkeho

        sprava, sender_address = client_socket.recvfrom(1500)  # Dostava fakturu od servera
        sprava = struct.unpack("!cI", sprava)  # Rozbali
        fakture = sprava[0]
        fragmentsnumber = sprava[1]

        if fakture == b'5':  # Flag 5 znamena ze
            if fragmentsnumber == number_of_packet:  # vsetko je ok
                print('Fakturu mam od packetu ', number_of_packet)
                number_of_packet = number_of_packet - 1
                continue
            if fragmentsnumber != number_of_packet:
                print('Nieco sa pokazilo pri packete ', number_of_packet)
                break

        if fakture == b'6':  # Flag 6 znamena ze
            print('Nieco sa pokazilo, skusim znovu')  # nieco sa pokazilo
            number_of_packet = number_of_packet
            # ARQ metoda pri posielani sprav sa nepouziva moc, lebo v vytvorenii
            # a detekcii chyb som sa zameral najviac v posielanii filov

    print("Sprava uspesne odoslana\n")


def client(client_socket, server_address):  # Menu pre klienta
    while True:

        print("0 for exit")
        print("1 for text message")
        print("2 for file message")
        print("5 for switching role")
        print("6 end communikation")

        udrz = Lock()
        stop_thread = False                                             # Definujem Thread
        def infinit_worker():
            while True:
                #    print("--> thread work")
                flagg = b'5'
                integger = 1
                sprava = struct.pack("!cI", flagg, integger)            # Posle ziadost na server
                client_socket.sendto(sprava, server_address)

                sprava, sender_address = client_socket.recvfrom(1500)   # Prijme ziadost zo servera

                if sprava == b'5':
                #    print('its ok')
                    premenna = ''
                elif sprava == None:
                    print('crash')

                udrz.acquire()
                if stop_thread is True:
                    break
                udrz.release()
                sleep(3)
        # print("Stop infinit_worker()")
        th = Thread(target=infinit_worker)
        th.start()              # Vytvorim a startnem Thread
        sleep(2)

        choice_client = input()

        udrz.acquire()
        stop_thread = True      # Stopnem Thread
        udrz.release()

        if choice_client == '1':
            flag = b'2'
            print("Zadajte spravu: ")
            client_massage = input()
            print("Zadajte velkost paketu: ")
            packetsize = int(input())
            while packetsize >= 1464 or packetsize <= 0:  # Osetri velkost paketu
                print("Neplatny vstupny udaj \n")
            fragmentsnumber = math.ceil(len(client_massage) / packetsize)  # Spocita kolko bude paketov
            print("Dlzka spravy je ", len(client_massage), "--- Packetov bude ", fragmentsnumber)
            sprava = struct.pack("!cI", flag, fragmentsnumber)  # Zabali udaje do packetu ze co
            client_socket.sendto(sprava, server_address)  # ide robit a posle serverovi
            send_message(client_socket, server_address, client_massage, packetsize, fragmentsnumber)  # Funkcia

        elif choice_client == '2':
            flag = b'3'
            print('Zadajte cestu k fajlu')
            filename = input()
            with open(filename, mode='rb') as file:  # Hned zakoduje file
                filestuct = file.read()
            print("Zadajte velkost paketu: ")
            packetsize = int(input())
            print("Chcete chybu v datach? 1 ano 0 nie")  # Ze ci
            chyba = int(input())  # pouzivatel
            if chyba == 1:  # chce chyby
                print("V akom pakete?")
                chyba = int(input())
            while packetsize >= 1464 or packetsize <= 1:  # Osetri velkost paketu
                print("Neplatny vstupny udaj \n")
            fragmentsnumber = math.ceil(len(filestuct) / packetsize)  # Spocita kolko bude paketov
            print("Dlzka spravy je ", len(filestuct), "--- Packetov bude ", fragmentsnumber)
            sprava = struct.pack("!cI", flag, fragmentsnumber)  # Zabali udaje do packetu ze co
            client_socket.sendto(sprava, server_address)  # ide robit a posle serverovi
            send_file(client_socket, server_address, filename, packetsize, fragmentsnumber, chyba)  # Funkcia

        if choice_client == '5':
            print("Changing roles")
            flag = b'9'
            integger = 1
            sprava = struct.pack("!cI", flag, integger)  # Pocle ziadost na server
            client_socket.sendto(sprava, server_address)
            changingroles(client_socket, server_address)  # Ide do funkcii

        if choice_client == '6':
            print("Bye-Bye")
            flag = b'6'
            integger = 1
            sprava = struct.pack("!cI", flag, integger)  # Pocle ziadost na server
            client_socket.sendto(sprava, server_address)
            bye_bye(client_socket, server_address)  # Ide do funkcii

        else:
            print("Try to input something different")


def bye_bye(client_socket, server_address):  # Koniec spojenia
    sprava, server_address = client_socket.recvfrom(1500)
    sprava = struct.unpack("!c", sprava)
    flag = sprava[0]  # Dostane packet od servera
    if flag == b'6':  # ze ziadost prijata
        client_socket.close()  # zavrie socket a prejde


def changingroles(client_socket, server_address):  # Zmena rol
    sprava, server_address = client_socket.recvfrom(1500)
    sprava = struct.unpack("!c", sprava)
    flag = sprava[0]  # Dostane packet od servera
    if flag == b'9':  # ze ziadost prijata
        client_socket.close()  # zavrie socket a prejde
        server_login()  # do loginu


def client_login():  # Login pre klienta
    print("Zadajte IP servera")
    ip = input()  # Zada IP servera
    print("Zadajte PORT servera")
    port = input()  # Zada port servera

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Inet - ETHERNET    DGRAM - UDP
    client_socket.bind(("0.0.0.0", 0))  # bind
    print('klientsky port:', client_socket.getsockname()[1])  # Vypise port klienta

    server_address = (ip, int(port))  # Odosle flag serveru
    client_socket.sendto(b'1', server_address)

    while True:
        data, server_address = client_socket.recvfrom(1500)  # Dostane flag a prejde do menu
        if data == b'1':
            client(client_socket, server_address)  # Prechod do menu pri uspesnom spojeni


##############################################################################################################################################################################################################################################################


def main():  # Len menu, kde pouzivatel si zvoli rolu
    print("1 for client")
    print("2 for server")
    print("3 to exit")
    choice = input()
    if choice == '1':
        client_login()
    elif choice == '2':
        server_login()
    else:
        print("Try to input something different")


main()

# C:\Users\user\Desktop\1665496616405.png