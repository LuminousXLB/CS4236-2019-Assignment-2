import socket

HOST = "localhost"
PORT = 5000

f = open("port", "r")
lines = f.readlines()
PORT = int(lines[0].strip())


def pad_oracle(str1, str2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    message = "pad_oracle," + str1 + "," + str2 + "\n"
    sock.sendall(message.encode('ascii'))
    data = sock.recv(1)
    return data


def dec_oracle(str1, str2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    message = "dec_oracle," + str1 + "," + str2 + "\n"
    sock.sendall(message.encode('ascii'))
    data = sock.recv(18)
    return data
