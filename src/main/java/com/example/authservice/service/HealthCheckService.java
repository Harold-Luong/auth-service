package com.example.authservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

@Service
@RequiredArgsConstructor
public class HealthCheckService {
    private final DataSource dataSource;

    public boolean isDatabaseConnected() {
        try (Connection connection = dataSource.getConnection()) {
            // Bounds validation only; acquiring a connection uses the pool's timeout.
            return connection.isValid(2);
        } catch (SQLException e) {
            return false;
        }
    }
}
