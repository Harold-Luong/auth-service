package com.ecommerce.auth.kafka;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserProducer {

    private static final Logger logger = LoggerFactory.getLogger(UserProducer.class);
    private final KafkaTemplate<String, UserCreatedEvent> kafkaTemplate;

    public void sendUserCreatedEvent(UserCreatedEvent event) {
        logger.info("Sending UserCreatedEvent to Kafka: {}", event);
        String USER_CREATED_TOPIC = "user.created";
        kafkaTemplate.send(USER_CREATED_TOPIC, event);
    }
}
