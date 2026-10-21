USE ai_security_agent;

CREATE TABLE endpoints (
    endpoint_id   INT AUTO_INCREMENT PRIMARY KEY,
    ip_address    VARCHAR(45)  NOT NULL,
    hostname      VARCHAR(255) NOT NULL,
    os_version    VARCHAR(100)
);

CREATE TABLE scripts (
    script_id     INT AUTO_INCREMENT PRIMARY KEY,
    endpoint_id   INT NOT NULL,
    script_name   VARCHAR(255) NOT NULL,
    script_type   VARCHAR(50),
    schedule      VARCHAR(100),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id)
);

CREATE TABLE anthropic_api (
    request_id    INT AUTO_INCREMENT PRIMARY KEY,
    script_id     INT NOT NULL,
    requested_at  DATETIME NOT NULL,
    api_status    VARCHAR(50),
    FOREIGN KEY (script_id) REFERENCES scripts(script_id)
);

CREATE TABLE security_analysts (
    staff_id      INT AUTO_INCREMENT PRIMARY KEY,
    staff_name    VARCHAR(255) NOT NULL,
    staff_role    VARCHAR(100),
    staff_email   VARCHAR(255) NOT NULL UNIQUE
);

CREATE TABLE managers_higher_ups (
    manager_id          INT AUTO_INCREMENT PRIMARY KEY,
    manager_name        VARCHAR(255) NOT NULL,
    manager_email       VARCHAR(255) NOT NULL UNIQUE,
    manager_department  VARCHAR(100)
);

CREATE TABLE email_reporting (
    report_id      INT AUTO_INCREMENT PRIMARY KEY,
    request_id     INT NOT NULL,
    report_type    VARCHAR(50) NOT NULL,
    generated_at   DATETIME NOT NULL,
    email_status   VARCHAR(50),
    reviewed_by    INT,
    FOREIGN KEY (request_id)  REFERENCES anthropic_api(request_id),
    FOREIGN KEY (reviewed_by) REFERENCES security_analysts(staff_id)
);

CREATE TABLE report_recipients (
    report_id    INT NOT NULL,
    manager_id   INT NOT NULL,
    PRIMARY KEY (report_id, manager_id),
    FOREIGN KEY (report_id)  REFERENCES email_reporting(report_id),
    FOREIGN KEY (manager_id) REFERENCES managers_higher_ups(manager_id)
);

INSERT INTO security_analysts (staff_name, staff_role, staff_email)
VALUES ('Mitchell Sheiry', 'Security Analyst / Developer', 'analyst@example.com');
