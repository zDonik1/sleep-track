-- name: UserExists :one
SELECT EXISTS(
    SELECT 1
    FROM Users
    WHERE Name = $1
);

-- name: GetUser :one
SELECT Name, PassHash
FROM Users
WHERE Name = $1;

-- name: GetIntervals :many
SELECT Id, IntrStart AT TIME ZONE 'UTC', IntrEnd AT TIME ZONE 'UTC', Quality
FROM Intervals
WHERE Username = $1 AND (IntrStart <= $2 AND IntrEnd >= $3)
ORDER BY IntrStart;

-- name: CreateUser :exec
INSERT INTO Users(Name, PassHash) VALUES ($1,$2);

-- name: CreateInterval :one
INSERT INTO Intervals (IntrStart, IntrEnd, Quality, Username)
VALUES ($1,$2,$3,$4)
RETURNING Id;

-- name: Wipe :exec
DROP TABLE IF EXISTS Intervals, Users;
