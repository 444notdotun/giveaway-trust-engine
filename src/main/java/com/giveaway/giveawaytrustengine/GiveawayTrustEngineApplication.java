package com.giveaway.giveawaytrustengine;

import com.giveaway.giveawaytrustengine.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class GiveawayTrustEngineApplication {

    public static void main(String[] args) {
        SpringApplication.run(GiveawayTrustEngineApplication.class, args);
    }

}
