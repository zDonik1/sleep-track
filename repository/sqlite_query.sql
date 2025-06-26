-- name: UserExists :one
SELECT EXISTS(
    SELECT 1
    FROM Users
    WHERE Name = ?
);

-- name: GetUser :one
SELECT Name, PassHash
FROM Users
WHERE Name = ?;

-- name: GetIntervals :many
SELECT Id, IntrStart, IntrEnd, Quality
FROM Intervals
WHERE Username = ? AND (IntrStart <= ? AND IntrEnd >= ?)
ORDER BY IntrStart;

-- name: CreateUser :exec
INSERT INTO Users(Name, PassHash) VALUES (?,?);

-- name: CreateInterval :one
INSERT INTO Intervals (IntrStart, IntrEnd, Quality, Username)
VALUES (?,?,?,?)
RETURNING Id;

-- name: WipeUsers :exec
DROP TABLE IF EXISTS Users;

-- name: WipeIntervals :exec
DROP TABLE IF EXISTS Intervals;
