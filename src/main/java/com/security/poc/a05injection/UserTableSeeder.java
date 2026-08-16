package com.security.poc.a05injection;

import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Seeds the {@code app_users} table used by the A05 SQL-injection demo.
 * Contains an "admin" row with a secret so the injection payload has something
 * juicy to exfiltrate.
 */
@Component
class UserTableSeeder implements CommandLineRunner {

    private final JdbcTemplate jdbc;

    UserTableSeeder(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void run(String... args) {
        jdbc.execute("""
            CREATE TABLE IF NOT EXISTS app_users (
                id       INT PRIMARY KEY,
                username VARCHAR(64),
                role     VARCHAR(32),
                secret   VARCHAR(128)
            )
        """);
        jdbc.update("DELETE FROM app_users");
        jdbc.update("INSERT INTO app_users VALUES (1, ?, ?, ?)", "salman", "USER",  "personal-note-1");
        jdbc.update("INSERT INTO app_users VALUES (2, ?, ?, ?)", "bob",    "USER",  "personal-note-2");
        jdbc.update("INSERT INTO app_users VALUES (3, ?, ?, ?)", "admin",  "ADMIN", "TOP-SECRET-KEY");
    }
}
