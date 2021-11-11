\connect mycodeplug
INSERT INTO "users" ("created_ip", "email", "name")
VALUES ('127.0.0.1', 'admin@mycodeplug.com', 'Administrator');

INSERT INTO "groups" ("created_ip", "owner", "members")
VALUES ('127.0.0.1', 1, '{1}');

INSERT INTO "channel"
	("channel_uuid", "owner", "group_id", "source")
VALUES
	('95a0a797-64c3-458f-9f4f-b02332f84dc8', 1, 1, 'sample');

INSERT INTO "channel_name" ("name", "alt_name_16", "alt_name_6")
VALUES (
    'National 2m FM Simplex Calling Frequency',
    '146.52 Calling',
    '2MCALL'
);

INSERT INTO "channel_revision"
	("user_id", "channel_uuid", "ts", "name_id", "frequency", "f_offset", "power",
	 "rx_only", "mode")
VALUES
	(1, '95a0a797-64c3-458f-9f4f-b02332f84dc8', now(), 1, 146.520, 0.0, 'high', false, 'FM');

INSERT INTO "channel_revision"
	("user_id", "channel_uuid", "ts", "power")
VALUES
	(1, '95a0a797-64c3-458f-9f4f-b02332f84dc8', now(), 'low');
