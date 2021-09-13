CREATE TABLE IF NOT EXISTS users  (
    id           	serial PRIMARY KEY,
	fname        	varchar(255),
	lname        	varchar(255),
    email        	varchar(255) UNIQUE,
    password     	varchar(255),
	organisation 	varchar(255), 
    admin        	boolean DEFAULT '0',
    created_at   	TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_secret_keys  (
    id           	serial PRIMARY KEY,
    uid          	int,
	secret_key      varchar(255),
	expire_date     TIMESTAMP
    created_at   	TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);