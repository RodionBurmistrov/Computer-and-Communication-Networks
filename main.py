from scapy.all import *
import ruamel.yaml.scalarstring
import argparse

#listy na fungovanie rozsirenia ARP
ARPlistcomplete = []
ARPlistfailed = []
GLOBALARP = []

#zapisem ipcka do pomocneho textoveho suboru
def ulohatri(ipsource):
    a = 0
    with open('Protocols/Ulohatri.txt', 'a') as f:
        f.write(ipsource + '\n')

#spocitam rovnake ipcka, kolko odoslali paketov a schvam do listu, ktory potom zapisem do yaml
def ulohatripocitanie(ipvstyri):
    lines = []
    itemcounts = {}
    with open('Protocols/Ulohatri.txt') as f:
        for item in f:
            lines.append(item)
    for i in lines:
        c = lines.count(i)
        itemcounts.update({i: c})

    with open('Protocols/Ulohatri.txt', 'w') as f:
        for i in itemcounts:
            f.write(i.strip() + ':' + str(itemcounts[i]) + '\n')
            a = i.strip()
            ipvstyri.append({
                'node': a,
                'number_of_sent_packets': itemcounts[i]
            })

#zistim ake ip odoslalo ich najviac

#poznamka: da sa aj povedat presne cislo paketov, ale nie som si isty ci to treba,
#kedze v ukazkovom yaml to nakonci nebolo, do ipcount treba pridat navyse len 1 premennu
def ulohatrimax(ipcount):
    sourcecount = 0
    with open('Protocols/Ulohatri.txt') as file:
        for line in file:
            line = line.strip()
            splitline = line.split(':')
            if int(splitline[1]) > sourcecount:
                sourcecount = int(splitline[1])
                ipcount.clear()
                ipcount.append(splitline[0])
            elif int(splitline[1]) == sourcecount:
                ipcount.append(splitline[0])

#main
def main():
    pcap = rdpcap("Wireshark/trace-15.pcap")  #cesta na pcap
    ramec = 1
    file = open(r'Yaml/yaml.yaml', 'w') #cesta na yaml
    file.write("name: PKS2022/23\npcap_name: all.pcap\n") #napisem zaciatok yamlu

    #deklaracia potrebnych premennych/listov
    packets = []

    TFTPlist = []

    appProtocol = ''

    tftpnumber = 0

    GLOBALsrc = 0
    GLOBALdst = 0
    GLOBALips = ''
    GLOBALipd = ''
    GLOBALa = 0

    #pridavam parser, pre nacitanie filtra cez comandline
    parser = argparse.ArgumentParser()
    parser.add_argument('-p')
    args = parser.parse_args()

    # doplnok k parseru na citanie filtru
    argum = 'net'
    if args.p:
        argum = args.p
    with open('Protocols/ProtokolyStvorka.txt') as PS:
        for line in PS:
            if str(line) == str(argum):
                continue
            else:
                break
#pozeram postupne kazdy jediny packet cez cyklus
    for packet in pcap:

        print("ramec", ramec)

#dlzka ramcu a zistim dlzku prenesenu do media
        API = packet.wirelen
        Media = API + 4
        if Media < 64:
            Media = 64

      #  print("Dlzka ramcu pcap API – ", API, " B")
      #  print("Dlzka ramca prenasaneho po mediu – ", Media, " B")

#pozeram na konkretne miesto v pakete, aby zistit typ ramca
        outputtype = ''
        if raw(packet)[12] < 0x06:                          #russianblogs.com/article/31441486657/
            if raw(packet)[14] == 0xFF:                     #1534 05DC HRANICNA HODNOTA
                outputtype = ('IEEE 802.3 RAW')
            elif raw(packet)[14] == 0xAA:
                outputtype = ('IEEE 802.3 LLC & SNAP')
            else:
                outputtype = ('IEEE 802.3 LLC')
        else:
            outputtype = ('Ethernet II')

#takym istym sposobom zistim aj Zdrojovu a aj cielovu MAC adresu
        outputzdroj = (':' .join('{:02X}'.format(r) for r in raw(packet)[6:12]))
        outputciel = (':' .join('{:02X}'.format(r) for r in raw(packet)[0:6]))

#ciklus na scitanie jednotlivych bajtov ramca v hexadecimalnom tvare
        #print(raw(packet).hex())
        fullPacketFormatted = ''
        fullPacket = ''
        for i in range(0, packet.wirelen*2, 2):
            if i % 32 == 0:
                fullPacket = fullPacket[:-1]
                fullPacket += '\n'
            fullPacket += raw(packet).hex()[i:i+2].upper() + ' '
        fullPacket = fullPacket.strip()
        fullPacket = fullPacket + '\n'
        print()

#program sa odvetvi, ak tym ramca je Ethernet II
        if outputtype == ('Ethernet II'):
            detector = 0
#zistim source a destination ip-cok, schovam si ich v potrebnom formate
            ipsource = ('.'.join('{:02X}'.format(r) for r in raw(packet)[26:30]))
            ipsourcee = int(ipsource[0:2], base=16), int(ipsource[3:5], base=16), int(ipsource[6:8], base=16), int(ipsource[9:11], base=16)
            ipsource = ('.'.join(str(r) for r in ipsourcee))

            ipdestination = ('.'.join('{:02X}'.format(r) for r in raw(packet)[30:34]))
            ipdestinationn = int(ipdestination[0:2], base=16), int(ipdestination[3:5], base=16), int(ipdestination[6:8],base=16), int(ipdestination[9:11], base=16)
            ipdestination = ('.'.join(str(r) for r in ipdestinationn))
        #zistim vnoreny protokol v hlavicke ramca patri do nejakeho znameho. Uvediem mu meno
            vnorenyTYP = (''.join('{:02X}'.format(r) for r in raw(packet)[12:14]))
            with open('Protocols/VnorenyTyp.txt') as VT:
                for line in VT:
                    line = line.strip()
                    splitline = line.split(':')
                    if splitline[0] == vnorenyTYP:
                        vnorenyT = splitline[1]
        #ak je to IPv4 tak este raz pozriem ip-cka (pre istotu som to spravil este raz) a pozriem na vnoreny protokol
                        if vnorenyT == ('IPv4'):
                            ipsource = ('.'.join('{:02X}'.format(r) for r in raw(packet)[26:30]))
                            ipsourcee = int(ipsource[0:2], base=16), int(ipsource[3:5], base=16), int(ipsource[6:8],base=16), int(ipsource[9:11], base=16)
                            ipsource = ('.'.join(str(r) for r in ipsourcee))

                            ipdestination = ('.'.join('{:02X}'.format(r) for r in raw(packet)[30:34]))
                            ipdestinationn = int(ipdestination[0:2], base=16), int(ipdestination[3:5], base=16), int(ipdestination[6:8], base=16), int(ipdestination[9:11], base=16)
                            ipdestination = ('.'.join(str(r) for r in ipdestinationn))

                            vnorenyPROTOCOL = (''.join('{:02X}'.format(r) for r in raw(packet)[23:24]))
                            ulohatri(ipsource)
                #porovnavam s textakom
                            with open('Protocols/VnorenyPtorokol.txt') as VP:
                                for line in VP:
                                    line = line.strip()
                                    splitline = line.split(':')
                                    if splitline[0] == vnorenyPROTOCOL:
                                        vnorenyP = splitline[1]

                            #ak je to TCP tak pozriem si na porty a zistim ci ich poznam
                                        if vnorenyP == ('TCP'):
                                            src = str(int((''.join('{:02X}'.format(r) for r in raw(packet)[34:36])), base=16))
                                            dst = str(int((''.join('{:02X}'.format(r) for r in raw(packet)[36:38])), base=16))
                                    #porovnavam s textakmi
                                            with open('Protocols/TCP.txt') as TCPtxt:
                                                for line1 in TCPtxt:
                                                    line1 = line1.strip()
                                                    splitline = line1.split(':')
                                                    if splitline[0] == src:
                                                        appProtocol = splitline[1]
                                                        src = int(src)
                                                        detector = 1                                #detektor mi pomaha na konci zapisat udaje do YAMLu
                                                    elif splitline[0] == dst:
                                                        src = int(src)
                                                        appProtocol = splitline[1]
                                                        dst = int(dst)
                                                        detector = 1

                            # ak je to UDP tak pozriem si na porty a zistim ci ich poznam
                                        if vnorenyP == ('UDP'):
                                            src = str(int((''.join('{:02X}'.format(r) for r in raw(packet)[34:36])), base=16))
                                            dst = str(int((''.join('{:02X}'.format(r) for r in raw(packet)[36:38])), base=16))
                                    # porovnavam s textakmi
                                            with open('Protocols/UDP.txt') as UDPtxt:
                                                for line1 in UDPtxt:
                                                    line1 = line1.strip()
                                                    splitline = line1.split(':')
                                                    if splitline[0] == src:
                                                        appProtocol = splitline[1]
                                                        src = int(src)
                                                        detector = 1
                                                    elif splitline[0] == dst:
                                                        src = int(src)
                                                        appProtocol = splitline[1]
                                                        dst = int(dst)
                                                        detector = 1

                                            src = int(src)      #neviem na co to je, kedze to iste sa robi aj vyssie
                                            dst = int(dst)      #ale pre istotu to radsej nechavam

        # ak je to ARP tak este raz pozriem ip-cka, lebo tu sa nachadzaju na inom mieste a pozriem sa tam, kde sa nachaza
        #informacia o tom, ci je request alebo reply, to budem potrebovat dalej, ak mame filter na ARP
                        if vnorenyT == ('ARP'):
                            ipsource = ('.'.join('{:02X}'.format(r) for r in raw(packet)[28:32]))
                            ipsourcee = int(ipsource[0:2], base=16), int(ipsource[3:5], base=16), int(ipsource[6:8],base=16), int(ipsource[9:11], base=16)
                            ipsource = ('.'.join(str(r) for r in ipsourcee))

                            ipdestination = ('.'.join('{:02X}'.format(r) for r in raw(packet)[38:42]))
                            ipdestinationn = int(ipdestination[0:2], base=16), int(ipdestination[3:5], base=16), int(ipdestination[6:8], base=16), int(ipdestination[9:11], base=16)
                            ipdestination = ('.'.join(str(r) for r in ipdestinationn))

                            requestorreply = ('.'.join('{:02X}'.format(r) for r in raw(packet)[21:22]))

        # ak je to IPv6 tak prepisem ip-ka, lebo IPv6 ma uplne iny format
                        if vnorenyT == ('IPv6'):
                            ipsource = (''.join('{:02X}'.format(r) for r in (raw(packet)[22:38])))
                            ipsource = (':'.join(ipsource[i:i + 4] for i in range(0, len(ipsource), 4)))

                            ipdestination = (''.join('{:02X}'.format(r) for r in (raw(packet)[38:54])))
                            ipdestination = (':'.join(ipdestination[i:i + 4] for i in range(0, len(ipdestination), 4)))

            # 35-36 source port
            # 37-38 dest port
            # 24 - PROT
            #ip sause 26-30
            #ip dest 30-34
            # print(vnorenysus)
            # if vnorenysus == 0x0800:
            #     vnoreny = ('IPv4')
            # if vnorenysus == 0x86DD:
            #     vnoreny = ('IPv6')
            # if vnorenysus == 0x0806:
            #     vnoreny = ('ARP')

#ak mame filter ARP, tak poslem info na zvlastnu funkciu
        if argum == ('ARP'):
            if vnorenyT == ('ARP'):
                arpfunkcia(vnorenyT, ramec, API, Media, outputtype, outputzdroj, outputciel, ipsource, ipdestination, fullPacket, requestorreply)

#ak mame filter TFTP, tak rovno zacnem tu
        if argum == 'TFTP':
            if GLOBALa == 1: #zaciatok nie je tu, lebo premenna GLOBALa bude == 1 az ked sa stretne TFTP protokol prvy krat
                if (GLOBALsrc) == dst:
                    if (str(GLOBALipd) == ipsource) or (str(GLOBALipd) == ipdestination):
                        if (str(GLOBALips) == ipdestination) or (str(GLOBALips) == ipsource):
    #vyssie som porovnaval ze ci ten dalsi a dalsi paket splna podmienky komunikacii
    #ak ano, tak sa zapise do samotneho listu
                            TFTPlist.append({
                                'frame_number': ramec,
                                'len_frame_pcap': API,
                                'len_frame_medium': Media,
                                'frame_type': outputtype,
                                'src_mac': outputzdroj,
                                'dst_mac': outputciel,
                                'src_ip': ipsource,
                                'dst_ip': ipdestination,
                                'protocol': vnorenyP,
                                'src_port': src,
                                'dst_port': dst,
                                'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                            })
                            GLOBALsrc = src
                            GLOBALipd = ipdestination
                            GLOBALips = ipsource
    #ked komunikacia sa skonci, pomocne premenne sa vynuluju
            else:
                GLOBALa = 0
                GLOBALsrc = 0
                GLOBALipd = ''
                GLOBALips = ''

    #ak protokol je TFTP tak si zapisem jeho udaje do "Globalnych" premennych, aby mi pomohli dalej
            if appProtocol == 'TFTP':
                tftpnumber = tftpnumber + 1
                GLOBALsrc = src
                GLOBALipd = ipdestination
                GLOBALips = ipsource
                GLOBALa = 1
                TFTPlist.append({'NOVA KOMUNIKACIA': tftpnumber})
                TFTPlist.append({
                    'frame_number': ramec,
                    'len_frame_pcap': API,
                    'len_frame_medium': Media,
                    'frame_type': outputtype,
                    'src_mac': outputzdroj,
                    'dst_mac': outputciel,
                    'ether_type': vnorenyT,
                    'src_ip': ipsource,
                    'dst_ip': ipdestination,
                    'protocol': vnorenyP,
                    'src_port': src,
                    'dst_port': dst,
                    'app_protocol': appProtocol,
                    'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                })

########################################################################################################################
#koniec skumania paketu, pomocou ziskanych informacij zapisem informaciu do listu, ktory prejde do yaml.yaml co najkrajse
        if outputtype == ('Ethernet II'):
            if vnorenyT == ('IPv4'):
                if vnorenyP == ('TCP'):
                    if detector == 1:
                        packets.append({
                            'frame_number': ramec,
                            'len_frame_pcap': API,
                            'len_frame_medium': Media,
                            'frame_type': outputtype,
                            'src_mac': outputzdroj,
                            'dst_mac': outputciel,
                            'ether_type': vnorenyT,
                            'src_ip': ipsource,
                            'dst_ip': ipdestination,
                            'protocol': vnorenyP,
                            'src_port': src,
                            'dst_port': dst,
                            'app_protocol': appProtocol,
                            'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                        })
                    else:
                        packets.append({
                            'frame_number': ramec,
                            'len_frame_pcap': API,
                            'len_frame_medium': Media,
                            'frame_type': outputtype,
                            'src_mac': outputzdroj,
                            'dst_mac': outputciel,
                            'ether_type': vnorenyT,
                            'src_ip': ipsource,
                            'dst_ip': ipdestination,
                            'protocol': vnorenyP,
                            'src_port': src,
                            'dst_port': dst,
                            'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                        })
                if vnorenyP == ('UDP'):
                    if detector == 1:
                        packets.append({
                            'frame_number': ramec,
                            'len_frame_pcap': API,
                            'len_frame_medium': Media,
                            'frame_type': outputtype,
                            'src_mac': outputzdroj,
                            'dst_mac': outputciel,
                            'ether_type': vnorenyT,
                            'src_ip': ipsource,
                            'dst_ip': ipdestination,
                            'protocol': vnorenyP,
                            'src_port': src,
                            'dst_port': dst,
                            'app_protocol': appProtocol,
                            'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                        })
                    else:
                        packets.append({
                            'frame_number': ramec,
                            'len_frame_pcap': API,
                            'len_frame_medium': Media,
                            'frame_type': outputtype,
                            'src_mac': outputzdroj,
                            'dst_mac': outputciel,
                            'ether_type': vnorenyT,
                            'src_ip': ipsource,
                            'dst_ip': ipdestination,
                            'protocol': vnorenyP,
                            'src_port': src,
                            'dst_port': dst,
                            'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                        })
                else:
                    packets.append({
                        'frame_number': ramec,
                        'len_frame_pcap': API,
                        'len_frame_medium': Media,
                        'frame_type': outputtype,
                        'src_mac': outputzdroj,
                        'dst_mac': outputciel,
                        'ether_type': vnorenyT,
                        'src_ip': ipsource,
                        'dst_ip': ipdestination,
                        'protocol': vnorenyP,
                        'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                    })
            else:
                packets.append({
                    'frame_number': ramec,
                    'len_frame_pcap': API,
                    'len_frame_medium': Media,
                    'frame_type': outputtype,
                    'src_mac': outputzdroj,
                    'dst_mac': outputciel,
                    'ether_type': vnorenyT,
                    'src_ip': ipsource,
                    'dst_ip': ipdestination,
                    'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                })
        else:
            packets.append({
                'frame_number': ramec,
                'len_frame_pcap': API,
                'len_frame_medium': Media,
                'frame_type': outputtype,
                'src_mac': outputzdroj,
                'dst_mac': outputciel,
                'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
            })

#zvysim ramec o jedna
        ramec += 1
        appProtocol = ''

#ked skoncim pozerat vsetky pakety, tak zapisem do yaml.yaml vsetko co sme zistili z .pcap file-u
    yaml = ruamel.yaml.YAML()
    yaml.default_flow_style = False
    yaml.dump({"packets":packets}, file)
    ipvstyri = []
    ipcount = []
    ulohatripocitanie(ipvstyri)
    file.write("\n")
    yaml.dump({"ipv4_senders":ipvstyri}, file)
    file.write("\n")
    ulohatrimax(ipcount)
    yaml.dump({"max_send_packets_by":ipcount}, file)
    open('Protocols/Ulohatri.txt', 'w')

# ak filter je na TFTP tak zapisem zistene informacie do zvlastneho .yaml suboru
    if argum == ('TFTP'):
        filetftp = open(r'Yaml/yamlTFTP.yaml', 'w') #cesta na yaml
        filetftp.write("name: PKS2022/23\npcap_name: all.pcap\n\n")
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.dump({"packets":TFTPlist}, filetftp)

# ak filter je na ARP tak zapisem zistene informacie do zvlastneho .yaml suboru
    if argum == ('ARP'):
        filearp = open(r'Yaml/yamlARP.yaml', 'w') #cesta na yaml
        filearp.write("name: PKS2022/23\npcap_name: all.pcap\n\n")
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.dump({"COMPLETE":ARPlistcomplete}, filearp)
        yaml.dump({"NOT COMPLETE":ARPlistfailed}, filearp)

#funkcia na filter ARP, dostane ARP paket, ku ktoremu bude hladat dvojicu
def arpfunkcia(vnorenyT, ramec, API, Media, outputtype, outputzdroj, outputciel, ipsource, ipdestination, fullPacket, requestorreply):
    if vnorenyT == ('ARP'):
        new = 1

    #ak ARP je Request, tak rychlo prejdem vsetky pakety, zistim vsetky informacie o pakete a hlavne ci je to ARP
        if requestorreply == ('01'):
            REQUEST = 'REQUEST'
            pcap = rdpcap("Wireshark/trace-15.pcap")  # cesta na pcap
            rameclooking = 1

            for packetlooking in pcap:
                outputtypelooking = ''

                APIlooking = packetlooking.wirelen
                Medialooking = APIlooking + 4
                if Medialooking < 64:
                    Medialooking = 64

                if raw(packetlooking)[12] < 0x06:  # russianblogs.com/article/31441486657/
                    print('not that')
                else:
                    outputtypelooking = ('Ethernet II')

                outputzdrojlooking = (':'.join('{:02X}'.format(r) for r in raw(packetlooking)[6:12]))
                outputciellooking = (':'.join('{:02X}'.format(r) for r in raw(packetlooking)[0:6]))

                fullPacketlooking = ''
                for i in range(0, packetlooking.wirelen * 2, 2):
                    if i % 32 == 0:
                        fullPacketlooking = fullPacketlooking[:-1]
                        fullPacketlooking += '\n'
                    fullPacketlooking += raw(packetlooking).hex()[i:i + 2].upper() + ' '
                fullPacketlooking = fullPacketlooking.strip()
                fullPacketlooking = fullPacketlooking + '\n'

                if outputtypelooking == ('Ethernet II'):
                    vnorenyTYP = (''.join('{:02X}'.format(r) for r in raw(packetlooking)[12:14]))
                    with open('VnorenyTyp.txt') as VT:
                        for line in VT:
                            line = line.strip()
                            splitline = line.split(':')
                            if splitline[0] == vnorenyTYP:
                                vnorenyTlooking = splitline[1]

            #ak je to ARP, tak dozistujem ip-cka
                                if vnorenyTlooking == ('ARP'):
                                    ipsourcelooking = ('.'.join('{:02X}'.format(r) for r in raw(packetlooking)[28:32]))
                                    ipsourceelooking = int(ipsourcelooking[0:2], base=16), int(ipsourcelooking[3:5], base=16), int(
                                        ipsourcelooking[6:8], base=16), int(ipsourcelooking[9:11], base=16)
                                    ipsourcelooking = ('.'.join(str(r) for r in ipsourceelooking))

                                    ipdestinationlooking = ('.'.join('{:02X}'.format(r) for r in raw(packetlooking)[38:42]))
                                    ipdestinationnlooking = int(ipdestinationlooking[0:2], base=16), int(ipdestinationlooking[3:5],
                                                                                           base=16), int(
                                        ipdestinationlooking[6:8], base=16), int(ipdestinationlooking[9:11], base=16)
                                    ipdestinationlooking = ('.'.join(str(r) for r in ipdestinationnlooking))

                                    requestorreplylooking = ('.'.join('{:02X}'.format(r) for r in raw(packetlooking)[21:22]))

            #ak je to Reply, ktory este nebol najdeny tak zistim ci splna podmienky
            #a ak ano, tak zapisem si obydva pakety do listu kompletnych komunikacij
                                    if requestorreplylooking == ('02'):
                                        if rameclooking not in GLOBALARP:
                                            REPLY = 'REPLY'
                                            if ipdestination == ipsourcelooking:
                                                if ipsource == ipdestinationlooking:
                                                    ARPlistcomplete.append({
                                                        'number_comm': new,
                                                        'src_comm': ipsource,
                                                        'dst_comm': ipdestination,
                                                        'packets': ''
                                                    })
                                                    new = new + 1
                                                    ARPlistcomplete.append({
                                                        'frame_number': ramec,
                                                        'len_frame_pcap': API,
                                                        'len_frame_medium': Media,
                                                        'frame_type': outputtype,
                                                        'src_mac': outputzdroj,
                                                        'dst_mac': outputciel,
                                                        'ether_type': vnorenyT,
                                                        'arp_opcode':REQUEST,
                                                        'src_ip': ipsource,
                                                        'dst_ip': ipdestination,
                                                        'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                                                    })
                                                    ARPlistcomplete.append({
                                                        'frame_number': rameclooking,
                                                        'len_frame_pcap': APIlooking,
                                                        'len_frame_medium': Medialooking,
                                                        'frame_type': outputtypelooking,
                                                        'src_mac': outputzdrojlooking,
                                                        'dst_mac': outputciellooking,
                                                        'ether_type': vnorenyTlooking,
                                                        'arp_opcode': REPLY,
                                                        'src_ip': ipsourcelooking,
                                                        'dst_ip': ipdestinationlooking,
                                                        'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacketlooking)

                                                    })
                                                #zapisem oba ramca do listu pouzitych
                                                    GLOBALARP.append(ramec)
                                                    GLOBALARP.append(rameclooking)
                rameclooking = rameclooking + 1

        #ak sa par nenasiel, tak ramec sa zapise do listu nekompletnych komunikacij
            if ramec not in GLOBALARP:
                ARPlistfailed.append({
                    'number_comm': new,
                    'packets': ''
                })
                ARPlistfailed.append({
                    'frame_number': ramec,
                    'len_frame_pcap': API,
                    'len_frame_medium': Media,
                    'frame_type': outputtype,
                    'src_mac': outputzdroj,
                    'dst_mac': outputciel,
                    'ether_type': vnorenyT,
                    'arp_opcode': REQUEST,
                    'src_ip': ipsource,
                    'dst_ip': ipdestination,
                    'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                })


        if requestorreply == ('02'):
            if ramec not in GLOBALARP:
                REPLY = 'REPLY'
                ARPlistfailed.append({
                'number_comm': new,
                'packets': ''
                })
                ARPlistfailed.append({
                'frame_number': ramec,
                'len_frame_pcap': API,
                'len_frame_medium': Media,
                'frame_type': outputtype,
                'src_mac': outputzdroj,
                'dst_mac': outputciel,
                'ether_type': vnorenyT,
                'arp_opcode': REPLY,
                'src_ip': ipsource,
                'dst_ip': ipdestination,
                'hexa_frame': ruamel.yaml.scalarstring.LiteralScalarString(fullPacket)
                })




main()


#python validator.py -d yaml.yaml -s schema-all.yaml

# python main.py -p argument
