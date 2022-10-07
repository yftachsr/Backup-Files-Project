import sqlite3

ID_LENGTH = 16
NAME_LENGTH = 127
PUBLIC_KEY_SIZE = 160
AES_LENGTH = 32  # 256/8
FILE_NAME_LENGTH = 255
PATH_NAME_LENGTH = 255


class Database:
    CLIENTS_TABLE = 'clients'
    FILES_TABLE = 'files'

    def __init__(self, name):
        self.name = name

        self.executeScript(f"""
            CREATE TABLE IF NOT EXISTS {Database.CLIENTS_TABLE}(
                ID TEXT NOT NULL PRIMARY KEY,
                Name TEXT NOT NULL,
                PublicKey TEXT,
                LastSeen TEXT,
                AESKey TEXT );
        """)

        self.executeScript(f"""
            CREATE TABLE IF NOT EXISTS {Database.FILES_TABLE}(
                ID TEXT NOT NULL,
                FileName TEXT NOT NULL,
                PathName TEXT NOT NULL,
                Verified INTEGER,
                PRIMARY KEY (ID, FileName));
        """)

    def connect(self):
        conn = sqlite3.connect(self.name)
        conn.text_factory = bytes
        return conn

    def executeScript(self, script):
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except Exception as e:
            print(e)
        conn.close()

    def executeQuery(self, query, args, commit=False):
        result = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
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
        if not id or len(id) != ID_LENGTH:
            return False
        if not name or len(name) >= NAME_LENGTH:
            return False
        return self.executeQuery(f"INSERT INTO {Database.CLIENTS_TABLE} (ID, Name) VALUES (?, ?)", [id, name],
                                 True)

    def setPublicKey(self, id, key):
        if not key or len(key) != PUBLIC_KEY_SIZE:
            return False
        return self.executeQuery(f"UPDATE {Database.CLIENTS_TABLE} SET PublicKey = ? WHERE ID = ?", [key, id], True)

    def setAESKey(self, id, key):
        return self.executeQuery(f"UPDATE {Database.CLIENTS_TABLE} SET AESKey = ? WHERE ID = ?", [key, id], True)

    def getAESKey(self, id):
        return self.executeQuery(f"SELECT AESKey FROM {Database.CLIENTS_TABLE} WHERE ID = ?", [id])

    def getClientName(self, id):
        return self.executeQuery(f"SELECT Name FROM {Database.CLIENTS_TABLE} WHERE ID = ?", [id])

    def saveFile(self, id, filename, path, verified):
        return self.executeQuery(f"INSERT INTO {Database.FILES_TABLE} VALUES (?,?,?,?)", [id, filename, path, verified],
                                 True)

    def deleteFile(self, id, filename):
        return self.executeQuery(f"DELETE FROM {Database.FILES_TABLE} WHERE ID = ? AND FileName = ?", [id, filename], True)

    def setVerified(self, id, filename, verified):
        return self.executeQuery(f"UPDATE {Database.FILES_TABLE} SET Verified = ? WHERE ID = ? AND FileName = ?"
                                 , [verified, id, filename], True)

    def setLastSeen(self, id, time):
        return self.executeQuery(f"UPDATE {Database.CLIENTS_TABLE} SET LastSeen = ? WHERE ID = ?", [time, id], True)