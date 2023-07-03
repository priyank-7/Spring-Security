package com.security.Service;

import com.security.Entity.PasswordResetToken;
import com.security.Entity.User;
import com.security.Entity.VerificationToken;
import com.security.Model.UserModel;
import com.security.Repository.PasswordResetTokenRepository;
import com.security.Repository.UserRepository;
import com.security.Repository.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService{

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public User registerUser(UserModel userModel) {
        User user = new User();
        user.setEmail(userModel.getEmail());
        user.setFirstName(userModel.getFirstName());
        user.setLastName(userModel.getLastName());
        user.setRole("USER");
        user.setPassword(passwordEncoder.encode(userModel.getPassword()));
        userRepository.save(user);
        return user;
    }

    @Override
    public void saveVerificationTokenForUser(String token, User user) {
        VerificationToken verificationToken = new VerificationToken(user,token);
        this.verificationTokenRepository.save(verificationToken);
    }

    @Override
    public String validateVerificationToken(String token) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token);
        if (verificationToken == null){
            return "invalid";
        }
        User user  = verificationToken.getUser();
        Calendar calendar = Calendar.getInstance();
        if (verificationToken.getExpirationTime().getTime()-calendar.getTime().getTime() <= 0){
            verificationTokenRepository.delete(verificationToken);
            return "Token Expired";
        }
        user.setEnabled(true);
        userRepository.save(user);
        verificationTokenRepository.deleteByToken(token);
        return "valid";
    }

    @Override
    public VerificationToken getnerateNewVerificarionToken(String oldToken) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(oldToken);
        verificationToken.setToken(UUID.randomUUID().toString());
        verificationTokenRepository.save(verificationToken);
        return verificationToken;
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public void createPasswordResetTokenForUser(User user, String token) {
        PasswordResetToken passwordResetToken = new PasswordResetToken(user,token);
        passwordResetTokenRepository.save(passwordResetToken);
    }

    @Override
    public String validatePasswordResetToken(String token) {
        PasswordResetToken passwordResetToken = passwordResetTokenRepository.findByToken(token);
        if (passwordResetToken == null){
            return "invalid";
        }
        User user  = passwordResetToken.getUser();
        Calendar calendar = Calendar.getInstance();
        if (passwordResetToken.getExpirationTime().getTime()-calendar.getTime().getTime() <= 0){
            passwordResetTokenRepository.delete(passwordResetToken);
            return "Token Expired";
        }
        passwordResetTokenRepository.deleteByToken(token);
        return "Success";
    }

    @Override
    public Optional<User> getUserByPasswordResetToken(String token) {
        return Optional.ofNullable(passwordResetTokenRepository.findByToken(token).getUser());
    }

    @Override
    public void changePassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    @Override
    public boolean checkIfValidOldPassword(User user, String oldPassword) {
        return passwordEncoder.matches(oldPassword, user.getPassword());
    }
}
