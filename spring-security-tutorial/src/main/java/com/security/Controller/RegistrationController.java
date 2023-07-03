package com.security.Controller;

import com.security.Entity.User;
import com.security.Entity.VerificationToken;
import com.security.Event.RegistrationCompleteEvent;
import com.security.Model.PasswordModel;
import com.security.Model.UserModel;
import com.security.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.UUID;

@RestController
@Slf4j
public class RegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private ApplicationEventPublisher publisher;

    @PostMapping("/register")
    public String registerUser(@RequestBody UserModel userModel, final HttpServletRequest request){
        User user = userService.registerUser(userModel);
        publisher.publishEvent(new RegistrationCompleteEvent(user,applicationUrl(request)));
        return "Success";
    }

    @GetMapping("/verifyRegistration")
    public String veriftRegistration(@RequestParam("token") String token){
        String result = userService.validateVerificationToken(token);
        if(result.equalsIgnoreCase("valid")) {
            return "Verified";
        } else{
            return "Bad User";
        }
    }

    @GetMapping("/resendVerificationToken")
    public String resendVerificationToken(@RequestParam("token") String oldToken, HttpServletRequest request){
        VerificationToken verificationToken = userService.getnerateNewVerificarionToken(oldToken);
        User user = verificationToken.getUser();
        resendVerificationTokenMail(user, applicationUrl(request),verificationToken);
        return "Verification link was sent";
    }

    @PostMapping("/resetPassword")
    public String resetPassword(@RequestBody PasswordModel passwordModel, HttpServletRequest request){
        User user = userService.findUserByEmail(passwordModel.getEmail());
        String Url="";
        if (user != null){
            String token = UUID.randomUUID().toString();
            userService.createPasswordResetTokenForUser(user,token);
            Url = passwordResetTokenMail(user,applicationUrl(request),token);
        }
        return Url;
    }

    @PostMapping("/savePassword")
    public String savePassword(@RequestParam("token") String token, @RequestBody PasswordModel passwordModel){
        String result = userService.validatePasswordResetToken(token);
        if (!result.equalsIgnoreCase("Success")){
            return "Bad Request";
        }
        Optional<User> user = userService.getUserByPasswordResetToken(token);
        if (user.isPresent()){
            userService.changePassword(user.get(), passwordModel.getNewPassword());
            return "Success";
        }else{
            return "Invalid Token";
        }
    }

    @PostMapping("/changePassword")
    public String changePassword(@RequestBody PasswordModel passwordModel){
        User user = userService.findUserByEmail(passwordModel.getEmail());
        if (!userService.checkIfValidOldPassword(user,passwordModel.getOldPassword())){
            return "Invalid OldPassword";
        }
        // Save new password
        userService.changePassword(user,passwordModel.getNewPassword());
        return "Success";
    }


    private String passwordResetTokenMail(User user, String applicationUrl, String token) {
        String url = applicationUrl
                + "/savePassword?token="
                + token;
        return url;
    }


    private void resendVerificationTokenMail(User user, String applicationUrl, VerificationToken token) {
        String url = applicationUrl
                + "/verifyRegistration?token="
                + token.getToken();

        // Send verificationEmail()
        log.info("Clicking the link to verify your account: {}", url);
    }

    private String applicationUrl(HttpServletRequest request) {
        return "http://" +
                request.getServerName() +
                ":" +
                request.getServerPort() +
                request.getContextPath();
    }
}
