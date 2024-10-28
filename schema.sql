
    -- Drop existing tables if they exist
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS conversations;
    DROP TABLE IF EXISTS messages;

    -- Create users table
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );

    -- Create conversations table
    CREATE TABLE conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        contact TEXT NOT NULL,
        last_message_time TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );

    -- Create messages table
    CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        message_text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (conversation_id) REFERENCES conversations (id),
        FOREIGN KEY (sender_id) REFERENCES users (id)
    );
    