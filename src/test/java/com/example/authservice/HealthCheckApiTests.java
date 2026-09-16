package com.example.authservice;

import com.example.authservice.service.HealthCheckService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:health_check_test;DB_CLOSE_DELAY=-1")
@AutoConfigureMockMvc
class HealthCheckApiTests {
    @Autowired private MockMvc mvc;
    @MockitoSpyBean private HealthCheckService healthCheckService;

    @Test
    void checksRealTestDatabaseWithoutTokenOrQueryParameter() throws Exception {
        mvc.perform(get("/api/v1/auth/health-check"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.database").value("UP"));
    }

    @Test
    void returnsServiceUnavailableWhenDatabaseIsDown() throws Exception {
        doReturn(false).when(healthCheckService).isDatabaseConnected();

        mvc.perform(get("/api/v1/auth/health-check"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("DOWN"))
                .andExpect(jsonPath("$.database").value("DOWN"));
    }

    @Test
    void protectedEndpointsStillRequireAuthentication() throws Exception {
        mvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized());
    }
}
