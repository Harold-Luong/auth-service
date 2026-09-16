package com.example.authservice.service;

import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HealthCheckServiceTests {
    private final DataSource dataSource = mock(DataSource.class);
    private final Connection connection = mock(Connection.class);
    private final HealthCheckService service = new HealthCheckService(dataSource);

    @Test
    void validConnectionIsReturnedToPool() throws Exception {
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(anyInt())).thenReturn(true);

        assertTrue(service.isDatabaseConnected());
        verify(connection).close();
    }

    @Test
    void invalidConnectionIsReportedDownAndReturnedToPool() throws Exception {
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(anyInt())).thenReturn(false);

        assertFalse(service.isDatabaseConnected());
        verify(connection).close();
    }

    @Test
    void acquisitionFailureIsReportedDown() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException("Database unavailable"));

        assertFalse(service.isDatabaseConnected());
    }

    @Test
    void validationFailureStillReturnsConnectionToPool() throws Exception {
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(anyInt())).thenThrow(new SQLException("Connection lost"));

        assertFalse(service.isDatabaseConnected());
        verify(connection).close();
    }
}
