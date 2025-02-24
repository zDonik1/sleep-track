CREATE TABLE IF NOT EXISTS Users (
    Name TEXT PRIMARY KEY NOT NULL,
    PassHash BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS Intervals (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    Start DATETIME NOT NULL,
    End DATETIME NOT NULL,
    Quality INTEGER NOT NULL,
    Username TEXT,
    FOREIGN KEY (Username) REFERENCES Users(Name)
);
