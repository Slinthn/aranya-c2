CREATE TABLE exfil_commands(
    id INTEGER PRIMARY KEY,
    source_ip TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    stdout TEXT,
    stderr TEXT,
    timestamp TEXT NOT NULL DEFAULT current_timestamp
);

CREATE TABLE exfil_file(
    id INTEGER PRIMARY KEY,
    source_ip TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT current_timestamp
);
