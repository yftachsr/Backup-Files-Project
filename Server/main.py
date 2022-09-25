import socket
import struct
import uuid

PORT_FILE = "port.info"
PACKET_SIZE = 1024
CODE_REQ_REGISTER = 1100
CODE_REQ_RES = 1101
CODE_REQ_FILE = 1103
CODE_REQ_CRC_VALID = 1104
CODE_REQ_CRC_RETRY = 1105
CODE_REQ_CRC_FAIL = 1106
CODE_REGISTER = 2100
CODE_AES = 2102
CODE_FILE_CRC = 2103
CODE_MESSAGE = 2104
RESPONSE_HEADER_SIZE = 7
REQUEST_HEADER_SIZE = 23
UUID_SIZE = 16

class Response:
    def __init__(self, version, code, payloadsize, payload):
        self.version = version
        self.code = code
        self.payloadsize = payloadsize
        self.payload = payload

    def byteForPayload(self):
        return PACKET_SIZE - RESPONSE_HEADER_SIZE


class Request:
    def __init__(self, data):
        self.id = 0
        self.version = 0
        self.code = 0
        self.payloadsize = 0
        self.payload = b""

        try:
            #self.id = uuid.UUID(bytes_le=data[:UUID_SIZE])
            self.id = struct.unpack(f"<{UUID_SIZE}s", data[:UUID_SIZE])[0]
            self.version, self.code, self.payloadsize = struct.unpack("<BHL", data[UUID_SIZE:REQUEST_HEADER_SIZE + UUID_SIZE])
            rest = PACKET_SIZE - REQUEST_HEADER_SIZE
            if self.payloadsize < rest:
                rest = self.payloadsize
            self.payload = struct.unpack(f"<{rest}s", data[REQUEST_HEADER_SIZE:REQUEST_HEADER_SIZE + rest])
        except Exception as e:
            print(e)

    def byteForPayload(self):
        return PACKET_SIZE - REQUEST_HEADER_SIZE

class Server:
    DBNAME = "server.db"
    def __init__(self, port):
        self.port = port
        self.db = database.Database(Server.DBNAME)
        self.requests {
            CODE_REQ_REGISTER: self.registerClient,
            CODE_REQ_RES: self.handlePublicKey,
            CODE_REQ_FILE: self.handleFile,
            CODE
        }
def registerClient(req):
    if

def handleRequest(req):
    if req.code == CODE_REQ_REGISTER:
        registerClient(req)


def getPort(filename):
    defaultPort = 1234
    try:
        file = open(filename)
        port = int(file.readline().strip())
        file.close()
        return port
    except Exception as e:
        print(f"Failed to read port from {filename}: {e}\n using default port {defaultPort}.")
        return defaultPort


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", getPort(PORT_FILE)))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print("Connected by ", addr)
            while True:
                data = conn.recv(PACKET_SIZE)
                req = Request(data)
                handleRequest(req)
                text = data.decode("utf-8")
                print(f"Received message: {text}")
                print("Enter message ")
                reply = input()
                replydata = bytearray(reply, "utf-8")
                newdata = bytearray(PACKET_SIZE)
                for i in range(min(len(replydata), len(newdata))):
                    newdata[i] = replydata[i]
                conn.sendall(newdata)