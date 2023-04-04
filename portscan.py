
from pwn import log
from datetime import datetime
from colorama import init, Fore, Style
import time
import re
import socket
import threading
import os
import sys
import signal

#Colores
blue = Fore.BLUE
yellow = Fore.YELLOW
red = Fore.RED
white = Fore.WHITE
green = Fore.GREEN
purple = Fore.MAGENTA
cyan = Fore.CYAN
reset = Style.RESET_ALL


def def_handler(sig, frame):
    print(cyan + "\n[!] Saliendo...!\n" + reset)
    sys.exit(1)

#ctrl_c
signal.signal(signal.SIGINT, def_handler)


def xd():
    while True:
        parse = input(yellow + "Ingresa una dirección IP: " + reset)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parse):
            break
        else:
            log.info(red + "Debe ingresar una direccion IP" + reset)
    return parse
                                                                                

def Peticion(ipadress):

    command = "ping -c 1 " + ipadress
    response = os.popen(command).read()

    if "1 received" in response:
        print(blue + "\nHost Activo: " + white , ipadress)

def validarModo():
    while True:
        try:
            mode = int(input(yellow + "Ingrese el modo de escaneo: " + reset))
            if mode == 1 or mode == 2 or mode == 3 or mode == 4: 
                break
            else:
                log.info(red + "Debe ingresar el modo valido" + reset)
        except ValueError:

            log.info(red + "Debes ingresar un modo de uso" + reset)
    
    return mode

#os.system("clear")
print("""
█████    ███████ ██████   ██████╗       █████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔══██╗ █╔═══ █╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """)
print(purple +"\nUse mode: " + reset + blue + "python3 portscan.py \n")
print(yellow + "\t[+]" + reset +  red + " Opcion 1: " + reset + "Descubrir Hosts activos")
print(yellow + "\t[+]" + reset + red + " Opcion 2: " + reset + "Escanear puertos abiertos")

print(yellow + "\t\t[-]" + reset + red + " Modo 1: " + reset + "Escanear puertos mas conocidos " + cyan + "[Recomendado]")

print(yellow + "\t\t[-]" + reset + red + " Modo 2: " + reset + "Escanear todos los puertos 1-65545")
print(yellow + "\t\t[-]" + reset + red + " Modo 3: " + reset + "Escanear los primeros 1000 puertos")
print(yellow + "\t\t[-]" + reset + red + " Modo 4: " + reset + "Escanear los primeros 10000 puertos " + cyan + "[Recomendado]")
print(yellow + "\n[+]" + reset + red + " Presione (ctrl_c): " + reset + "Salir del Programa\n")

while True:
    try:
        numero = int(input(yellow + "Ingrese la opcion que desee realizar: " + reset))
        if numero == 1 or numero == 2:
            break
        else:
            log.info(red + "Debe ingresar una opcion valida" + reset)
    except ValueError:
        log.info(red + "Debes ingresar una opcion valida." + reset)


if numero == 1:
    parse = xd()
    parse = parse.split('.')
    new = parse[0] + "." + parse[1] + "." + parse[2] + "."
    for i in range(1,254):
        current = new + str(i)

        try:
            t = threading.Thread(target=Peticion,args=(current,))
            t.start()


        except socket.gaierror:
                print("El host no se puede resolver")
                sys.exit()

        except socket.error:
                print("El host no responde...")
                sys.exit()



elif numero == 2:
    parse = xd()
    target = socket.gethostbyname(parse.strip())
    mode = validarModo()
    def Scan(portscan):

        timeStart = datetime.now()
        print("\n")
        print(green)
        print("#"*50)
        print(blue + "Empezando escaneo del objetivo: " + white + f"{target}\n")
        print(blue + "Analisis iniciado a las: " + white +  str(timeStart))
        print(green)
        print("#"*50)

        p1 = log.progress("")
        for port in portscan:
            p1.status(yellow + "Probando con puerto: " + white + f"{port}")
            s = socket.socket()

            conection = s.connect_ex((target,port))

            if conection == 0:

                print(white + "\nPuerto " + blue + f"{port}" + white + " abierto")
            s.close()

        timeEnd = datetime.now()

        finishTime = timeEnd - timeStart


        print(yellow + "\nEscaneo Completado en: " + white + str(finishTime) +"\n")

    def ObtainPorts(mode):
        portscan = []
        if mode == 1:
            r = open("ports.txt","r")
            for port in r:
                portscan.append(port.strip())
            portscan = map(int,portscan)
            return portscan

        elif mode == 2:
            for port in range(1, 65536):
                portscan.append(port)
            return portscan

        elif mode == 3:
            for port in range(1,1001):
                portscan.append(port)
            return portscan
        elif mode == 4:
            for port in range(1,10001):
                portscan.append(port)
            return portscan
        else:
            sys.exit()

    portscan = ObtainPorts(mode)

    try:
        t = threading.Thread(target=Scan, args=(portscan,))
        t.start()

    except socket.gaierror:
        print("No se puede resolver el host!")
        sys.exit()

    except socket.error:
        print("El host no responde...")
        sys.exit()
