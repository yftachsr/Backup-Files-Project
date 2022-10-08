import socket
import struct
import database
import selectors
from datetime import datetime
import uuid
import Crypto.Cipher
import Crypto.Random
import Crypto.Cipher.AES
from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import crc

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
CODE_ERROR = 2101
RESPONSE_HEADER_SIZE = 7
REQUEST_HEADER_SIZE = 23
UUID_SIZE = 16
SERVER_VERSION = 3
NAME_SIZE = 255
CONTENT_SIZE = 4
CRC_SIZE = 4
AES_KEY_LENGTH = 16


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
            data += struct.pack(f"<{UUID_SIZE}s", self.clientId)
            data += struct.pack(f"<{len(self.aesKey)}s", self.aesKey)
            return data
        except Exception as e:
            print(f"Exception when trying to pack public key response: {e}")
            return b""


class FileResponse:  # Didn't include Content Size because it makes no sense
    def __init__(self):
        self.header = ResponseHeader(CODE_RES_FILE_CRC)
        self.clientId = b""
        self.fileName = b""
        self.cksum = 0

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{UUID_SIZE}s", self.clientId)
            data += struct.pack(f"<{NAME_SIZE}s", self.fileName)
            data += struct.pack(f"<L", self.cksum)
            return data
        except Exception as e:
            print(f"Exception when trying to pack file response: {e}")
            return b""


class RequestHeader:
    def __init__(self):
        self.id = b""
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
    def __init__(self, header):
        self.header = header
        self.name = b""

    def unpack(self, payload):
        try:
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", payload[:NAME_SIZE])[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except Exception as e:
            print(f"Exception when parsing client name: {e}")
            self.name = b""
            return False


class PublicKeyRequest:
    def __init__(self, header):
        self.header = header
        self.name = b""
        self.publicKey = b""

    def unpack(self, payload):
        try:
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", payload[:NAME_SIZE])[0].partition(b'\0')[0].decode("utf-8"))
            self.publicKey = struct.unpack(f"<{database.PUBLIC_KEY_SIZE}s", payload[NAME_SIZE:NAME_SIZE + database.PUBLIC_KEY_SIZE])[0]
            return True
        except Exception as e:
            print(f"Exception when trying to unpack public key request: {e}")
            self.name = b""
            self.publicKey = b""
            return False


class FileRequest:
    def __init__(self, header):
        self.header = header
        self.contentSize = 0
        self.fileName = ""
        self.message = b""

    def unpack(self, data):
        try:
            self.contentSize = struct.unpack("<L", data[:CONTENT_SIZE])[0]
            self.fileName = str(struct.unpack(f"<{NAME_SIZE}s", data[CONTENT_SIZE:CONTENT_SIZE + NAME_SIZE])[0]
                                .partition(b'\0')[0].decode("utf-8"))
            self.message = struct.unpack(f"<{self.contentSize}s",
                                         data[CONTENT_SIZE + NAME_SIZE:CONTENT_SIZE + NAME_SIZE + self.contentSize])[0]

            return True
        except Exception as e:
            print(f"Exception when trying to unpack file request: {e}")
            self.contentSize = 0
            self.fileName = ""
            self.message = b""
            return False


class CrcRequest:
    def __init__(self, header):
        self.header = header
        self.filename = b""

    def unpack(self, data):
        try:
            self.filename = str(
                struct.unpack(f"<{NAME_SIZE}s", data[:NAME_SIZE])[0].partition(b'\0')[0].decode("utf-8"))
            return True
        except Exception as e:
            print(f"Exception when trying to unpack crc request: {e}")
            self.filename = b""
            return False


class Server:
    DBNAME = "server.db"
    MAX_QUEUE = 5
    Users_Files_Folder = "Users Files"

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
        try:
            os.mkdir(f"{Server.Users_Files_Folder}\\")  # Create folder for files sent from clients
        except FileExistsError:
            pass

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
        print("Client connected")
        conn, addr = sock.accept()
        conn.setblocking(True)
        self.sel.register(conn, selectors.EVENT_READ, self.receiveData)

    def receiveData(self, conn, mask):
        """Get the data from the client and handle the request accordingly"""
        done = False
        while not done:
            data = conn.recv(PACKET_SIZE)
            readenBytes = PACKET_SIZE
            if data:
                reqHeader = RequestHeader()
                success = False
                if reqHeader.unpack(data):
                    reqSize = REQUEST_HEADER_SIZE + reqHeader.payloadsize
                    while readenBytes < reqSize:  # Read the rest of the data
                        if PACKET_SIZE > reqSize - readenBytes:  # The number of bytes left is less than a packet
                            bytesNum = reqSize - readenBytes
                            data += conn.recv(bytesNum)
                            conn.recv(PACKET_SIZE - bytesNum)  # junk bytes
                            readenBytes += bytesNum
                        else:
                            data += conn.recv(PACKET_SIZE)
                            readenBytes += PACKET_SIZE
                    if reqHeader.code in self.requests.keys():  # Call the right handle function
                        success = self.requests[reqHeader.code](conn, reqHeader, data[REQUEST_HEADER_SIZE:])
                if not success:
                    resHeader = ResponseHeader(CODE_ERROR)
                    self.sendData(conn, resHeader.pack())
                    done = True
                self.db.setLastSeen(reqHeader.id, str(datetime.now()))
                if reqHeader.code == CODE_REQ_CRC_VALID or reqHeader.code == CODE_REQ_CRC_FAIL:
                    done = True
        self.sel.unregister(conn)
        conn.close()

    def sendData(self, conn, data):
        """Send the response as raw data in packets"""
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

    def saveFile(self, name, filename, content, newfile=True):
        """Save client files on the disk"""
        try:
            os.mkdir(f"{Server.Users_Files_Folder}\\{name}\\")  # Create a folder for the clients files
        except FileExistsError:
            pass
        except:
            return False
        try:
            if newfile:
                f = open(f"{Server.Users_Files_Folder}\\{name}\\{filename}", "w+b")  # Overwrite the file
            else:
                f = open(f"{Server.Users_Files_Folder}\\{name}\\{filename}", "a+b")  # Append to the file
            f.write(content)
            return True
        except Exception as e:
            return False

    def registerClient(self, conn, header, payload):
        """Handle client registration"""
        req = RegisterRequest(header)
        res = RegisterResponse()
        if not req.unpack(payload):
            return False
        try:
            if self.db.usernameExists(req.name):
                print(f"Client registration failure: username {req.name} already exists")
                return False
        except:
            print("Client registration failure: failed to connect to the database")
            return False
        newid = uuid.uuid4().bytes
        if not self.db.saveNewClient(newid, req.name):
            print(f"Client registration failure: client {req.name} couldn't be stored")
            return False
        print("Client ", req.name, f" registered with id: {newid}")
        res.clientId = newid
        res.header.payloadsize = UUID_SIZE
        return self.sendData(conn, res.pack())

    def generateAndEncryptAES(self, id, publicKey):
        """Generates an AES key and encrypts it with the public key"""
        key = Crypto.Random.get_random_bytes(AES_KEY_LENGTH)  # Generate AES key
        if not self.db.setAESKey(id, key):  # Save the AES key in the database
            print("Couldn't save the AES key in the database")
            return False
        cipher = PKCS1_OAEP.new(RSA.importKey(publicKey))
        return cipher.encrypt(key)  # Encrypt the AES key with the clients public key

    def calccksum(self, filepath):
        """Calculates check sum values for a file"""
        with open(filepath, "rb") as fd:
            digest = crc.crc32()
            while buf := fd.read(4096):
                digest.update(buf)
            return digest.digest()

    def handlePublicKey(self, conn, header, payload):
        """Saves the public key to the database and sends the encrypted AES key"""
        req = PublicKeyRequest(header)
        res = PublicKeyResponse()
        if not req.unpack(payload):
            return False
        if not self.db.setPublicKey(req.header.id, req.publicKey):
            print(f"Public key failure: public key couldn't be stored for client {req.name}")
            return False
        print(f"Public key stored for client {req.name}")
        res.clientId = req.header.id
        aeskey = self.generateAndEncryptAES(req.header.id, req.publicKey)
        if not aeskey:
            return False
        res.aesKey = aeskey
        res.header.payloadsize = UUID_SIZE + len(aeskey)
        print(f"Sending client {req.name} symmetric key")
        return self.sendData(conn, res.pack())

    def handleFile(self, conn, header, payload):
        """Decrypts clients file, saves it to the disk and in the database and sends the check sum"""
        req = FileRequest(header)
        res = FileResponse()
        if not req.unpack(payload):
            return False
        try:
            aeskey = self.db.getAESKey(req.header.id)[0][0]
        except:
            print(f"AES key wasn't found in the database for client {req.header.id}")
            return False
        try:
            clientname = str(self.db.getClientName(req.header.id)[0][0], 'utf-8')
        except:
            print(f"File save error: failed to retrieve name for client {req.header.id}")
            return False
        if not aeskey:
            print(f"File save error: failed to get AES key for client {clientname} form the database")
            return False
        cipher = Crypto.Cipher.AES.new(aeskey, Crypto.Cipher.AES.MODE_CBC, iv=b'\0' * 16)
        filepath = f"{Server.Users_Files_Folder}\\{clientname}\\{req.fileName}"
        if not self.saveFile(clientname, req.fileName, unpad(cipher.decrypt(req.message), Crypto.Cipher.AES.block_size)):  # Save to disk
            print(f"File save error: file {req.fileName} for client {clientname} couldn't be saved")
            return False
        print(f"File {req.fileName} was saved in the disk under {Server.Users_Files_Folder}\\{clientname}")
        if not self.db.deleteFile(req.header.id, req.fileName) or not self.db.saveFile(req.header.id, req.fileName, filepath, 0):  # Save to the database
            print(f"File save error: file {req.fileName} for client {clientname} couldn't be saved in the database")
            return False
        print(f"File {req.fileName} was saved in the database for client {clientname}")
        cksum = self.calccksum(filepath)
        res.clientId = req.header.id
        res.fileName = bytes(req.fileName, 'utf-8')
        res.cksum = cksum
        res.header.payloadsize = UUID_SIZE + NAME_SIZE + CRC_SIZE
        return self.sendData(conn, res.pack())

    def handleCRC(self, conn, header, payload):
        """Updates the verified value of a file in the database or deletes the file if corrupted"""
        req = CrcRequest(header)
        if not req.unpack(payload):
            return False
        try:
            clientname = str(self.db.getClientName(req.header.id)[0][0], 'utf-8')
        except:
            clientname = "(name failure)"
        if req.header.code == CODE_REQ_CRC_VALID:
            if not self.db.setVerified(req.header.id, req.filename, 1):
                print(f"CRC error: couldn't update verified for file {req.filename} client {req.header.id} in the database")
                return False
            print(f"CRC for client {clientname} file {req.filename} is valid")
        else:
            if not self.db.deleteFile(req.header.id, req.filename):
                print(f"CRC error: couldn't delete the corrupted file {req.filename} for client {req.header.id} from the database")
                return False
            print(f"CRC calculated for client {clientname} file {req.filename} is incorrect")
        return self.sendData(conn, ResponseHeader(CODE_RES_MESSAGE).pack())
