import socket
import struct
import database
import selectors
from datetime import datetime
import uuid

PORT_FILE = "port.info"
PACKET_SIZE = 1024
CODE_REQ_REGISTER = 1100
CODE_REQ_RES = 1101
CODE_REQ_FILE = 1103
CODE_REQ_CRC_VALID = 1104
CODE_REQ_CRC_RETRY = 1105
CODE_REQ_CRC_FAIL = 1106
CODE_RES_REGISTER = 2100
CODE_RES_AES = 2102
CODE_RES_FILE_CRC = 2103
CODE_RES_MESSAGE = 2104
CODE_ERROR = -1
RESPONSE_HEADER_SIZE = 7
REQUEST_HEADER_SIZE = 23
UUID_SIZE = 16
SERVER_VERSION = 3
NAME_SIZE = 255


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payloadsize = 0

    def pack(self):
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadsize)
        except Exception as e:
            print(f"Exception trying to pack response: {e}")
            return b""


class RegisterResponse:
    def __init__(self):
        self.header = ResponseHeader(CODE_RES_REGISTER)
        self.clientId = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{UUID_SIZE}s", self.clientId)
            return data
        except Exception as e:
            print(f"Exception when packing registration response: {e}")
            return b""

class PublicKeyResponse:
    def __init__(self):
        self.header = ResponseHeader(CODE_RES_AES)
        self.clientId = b""
        self.aesKey = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack()


class RequestHeader:
    def __init__(self):
        self.id = 0
        self.version = 0
        self.code = 0
        self.payloadsize = 0

    def unpack(self, data):
        try:
            self.id = struct.unpack(f"<{UUID_SIZE}s", data[:UUID_SIZE])[0]
            self.version, self.code, self.payloadsize = struct.unpack("<BHL", data[UUID_SIZE:REQUEST_HEADER_SIZE])
            return True
        except Exception as e:
            print(f"Exception when parsing the request: {e}")
            return False


class RegisterRequest:
    def __init__(self, reqHeader):
        self.reqHeader = reqHeader
        self.name = b""

    def unpack(self, payload):
        try:
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", payload)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except Exception as e:
            print(f"Exception when parsing client name: {e}")
            self.name = b""
            return False

class PublicKeyRequest:
    def __init__(self, reqHeader):
        self.reqHeader = reqHeader
        self.name = b""
        self.publicKey = b""

    def unpack(self, payload):
        try:
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", payload[:NAME_SIZE])[0].partition(b'\0')[0].decode("utf-8"))
            self.publicKey = struct.unpack(f"<{database.PUBLIC_KEY_SIZE}s", payload[NAME_SIZE:NAME_SIZE+database.PUBLIC_KEY_SIZE])[0]
            return True
        except Exception as e:
            print(f"Exception when trying to unpack public key request: {e}")
            self.name = b""
            self.publicKey = b""
            return False


class Server:
    DBNAME = "server.db"
    MAX_QUEUE = 5

    def __init__(self, port):
        self.port = port
        self.db = database.Database(Server.DBNAME)
        self.sel = selectors.DefaultSelector()
        self.requests = {
            CODE_REQ_REGISTER: self.registerClient,
            CODE_REQ_RES: self.handlePublicKey,
            CODE_REQ_FILE: self.handleFile,
            CODE_REQ_CRC_VALID: self.handleCRC,
            CODE_REQ_CRC_FAIL: self.handleCRC,
            CODE_REQ_CRC_RETRY: self.handleCRC
        }

    def start(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', self.port))
            sock.listen(Server.MAX_QUEUE)
            sock.setblocking(False)
            self.sel.register(sock, selectors.EVENT_READ, self.accept)
        except Exception as e:
            print(e)
        print(f"Listening on port {self.port}...")
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                print(f"Server loop exception: {e}")

    def accept(self, sock, mask):
        conn, addr = sock.accept()
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.receiveData)

    def receiveData(self, conn, mask):
        print("Client connected")
        data = conn.recv(PACKET_SIZE)
        readenBytes = PACKET_SIZE
        if data:
            reqHeader = RequestHeader()
            success = False
            if reqHeader.unpack(data):
                reqSize = REQUEST_HEADER_SIZE + reqHeader.payloadsize
                while readenBytes < reqSize: # Read the rest of the request
                    bytesNum = PACKET_SIZE
                    if PACKET_SIZE > reqSize - readenBytes: # The number of bytes left is less than a packet
                        bytesNum = reqSize - readenBytes
                    data += conn.recv(bytesNum)
                    readenBytes += bytesNum
                if reqHeader.code in self.requests.keys():
                    success = self.requests[reqHeader.code](conn, reqHeader, data[REQUEST_HEADER_SIZE:])
            if not success:
                resHeader = ResponseHeader(CODE_ERROR)
                self.sendData(conn, resHeader.pack())
            self.db.setLastSeen(reqHeader.id, str(datetime.now()))
        self.sel.unregister(conn)
        conn.close()

    def sendData(self, conn, data):
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > PACKET_SIZE:
                leftover = PACKET_SIZE
            toSend = data[sent:sent + leftover]
            if len(toSend) < PACKET_SIZE:
                toSend += bytearray(PACKET_SIZE - len(toSend))
            try:
                conn.send(toSend)
                sent += len(toSend)
            except Exception as e:
                print(f"Exception trying to send response to {conn}: {e}")
                return False
        print(f"Response sent to {conn}")
        return True

    def registerClient(self, conn, header, payload):
        req = RegisterRequest(header)
        res = RegisterResponse()
        if not req.unpack(payload):
            return False
        try:
            if self.db.usernameExists(req.name):
                print(f"Client registration failure: user name {req.name} already exists")
                return False
        except:
            print(f"Client registration failure: failed to connect to the database")
            return False
        if not self.db.saveNewClient(uuid.uuid4().hex, req.name):
            print(f"Client registration failure: client {req.name} couldn't be stored")
            return False
        print(f"Client {req.name} stored in the data base")
        res.clientId = req.reqHeader.id
        res.header.payloadsize = UUID_SIZE
        return self.sendData(conn, res.pack())

    def handlePublicKey(self, conn, header, payload):
        req = PublicKeyRequest(header)
        res = PublicKeyResponse()


def getPort(filename):
    defaultPort = 1234
    try:
        file = open(filename)
        port = int(file.readline().strip())
        file.close()
        return port
    except Exception as e:
        print(f"Failed to read port from {filename}: {e}\nUsing default port {defaultPort}.")
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
                req = RequestHeader(data)
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