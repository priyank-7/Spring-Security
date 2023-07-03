package com.security.Entity.Listiner;

import com.security.Entity.User;
import com.security.Event.RegistrationCompleteEvent;
import com.security.Service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@Slf4j
public class RegistrationCompleteEventListner implements ApplicationListener<RegistrationCompleteEvent>{

    @Autowired
    private UserService userService;

    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {
        // Create the verification token for thr User with link
        User user = event.getUser();
        String token = UUID.randomUUID().toString();
        userService.saveVerificationTokenForUser(token, user);

        // Send mail to user
        String url = event.getApplicationUrl()
                + "/verifyRegistration?token="
                + token;

        // Send verificationEmail()
        log.info("Clicking the link to verify your account: {}", url);
    }
}
