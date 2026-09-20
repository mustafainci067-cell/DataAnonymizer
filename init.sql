CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    credit_card VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO customers (full_name, email, credit_card) VALUES
('John Doe', 'john.doe@example.com', '1234-5678-9012-3456'),
('Jane Smith', 'jane.smith@example.com', '9876-5432-1098-7654'),
('Alice Johnson', 'alice.j@example.com', '1111-2222-3333-4444'),
('Bob Brown', 'bob.b@example.com', '5555-6666-7777-8888'),
('Charlie Davis', 'charlie.d@example.com', '9999-0000-1111-2222');
