import sqlite3

ID_LENGTH = 16
NAME_LENGTH = 127
PUBLIC_KEY_SIZE = 160
AES_LENGTH = 32 #256/8
FILE_NAME_LENGTH = 255
PATH_NAME_LENGTH = 255


class Database:
    CLIENTS_TABLE = 'clients'
    FILES_TABLE = 'files'

    def __init__(self, name):
        self.name = name

        self.executeScript(f"""
            CREATE TABLE {Database.CLIENTS_TABLE}(
                ID TEXT NOT NULL PRIMARY KEY,
                Name TEXT NOT NULL,
                PublicKey TEXT,
                LastSeen TEXT,
                AESKey TEXT );
        """)

        self.executeScript(f"""
            CREATE TABLE {Database.FILES_TABLE}(
                ID TEXT NOT NULL PRIMARY KEY,
                FileName TEXT NOT NULL,
                PathName TEXT NOT NULL,
                Verified INTEGER, 
        """)

    def connect(self):
        conn = sqlite3.connet(self.name)
        conn.text_factory = bytes
        return conn

    def executeScript(self, script):
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except:
            pass
        conn.close()

    def executeQuery(self, query, args, commit=False):
        result = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execut(query, args)
            if commit:
                conn.commit()
                result = True
            else:
                result = cur.fetchall()
        except Exception as e:
            print(f"Exception when executing database query: {e}")
        conn.close()
        return result

    def usernameExists(self, name):
        result = self.executeQuery(f"SELECT * FROM {Database.CLIENTS_TABLE} WHERE Name = ?", [name])
        if not result:
            return False
        return len(result) > 0

    def saveNewClient(self, id, name):
        idbytes = bytes.fromhex(id)
        if not idbytes or len(idbytes) != ID_LENGTH:
            return False
        if not name or len(name) != NAME_LENGTH:
            return False
        return self.executeQuery(f"INSERT INTO {Database.CLIENTS_TABLE} (ID, Name) VALUES (?, ?)", [idbytes, name], True)

    def setPublicKey(self, id, key):
        if not key or len(key) != PUBLIC_KEY_SIZE:
            return False
        return self.executeQuery(f"UPDATE {Database.CLIENTS_TABLE} SET PublicKey = ? WHERE ID = ?", [key, id])