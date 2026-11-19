package com.vulnwatch.search;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.net.ConnectException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-layer test (no database, Elasticsearch or Kafka): when Elasticsearch is unavailable the search
 * endpoint answers 503 with a problem detail instead of a generic 500.
 */
@WebMvcTest(CveSearchController.class)
class SearchUnavailableApiTest {

    @Autowired
    MockMvc mockMvc;

    @MockitoBean
    CveSearchService searchService;

    @Test
    void searchAnswers503WhenElasticsearchIsUnavailable() throws Exception {
        when(searchService.search(anyString(), any(), anyInt(), anyInt())).thenThrow(
                SearchUnavailableException.from("Search", new ConnectException("Connection refused")));

        mockMvc.perform(get("/api/cves/search").param("q", "overflow"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").value("Search unavailable"))
                .andExpect(jsonPath("$.status").value(503));
    }
}
