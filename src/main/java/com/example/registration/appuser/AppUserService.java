package com.example.registration.appuser;

import com.example.registration.registration.token.ConfirmationToken;
import com.example.registration.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

  private static final String USER_NOT_FOUND_MSG = "user with email %s not found";

  private final AppUserRepository appUserRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;
  private final ConfirmationTokenService confirmationTokenService;

  @Override
  public UserDetails loadUserByUsername(String email) {
    return appUserRepository
        .findByEmail(email)
        .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
  }

  @Transactional
  public String singUpUser(AppUser appUser) {
    boolean userExists = appUserRepository.findByEmail(appUser.getEmail()).isPresent();

    if (userExists) {
      throw new IllegalStateException("email already taken");
    }

    String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());

    appUser.setPassword(encodedPassword);

    appUserRepository.save(appUser);

    String token = UUID.randomUUID().toString();

    ConfirmationToken confirmationToken =
        new ConfirmationToken(
            token, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), appUser);

    confirmationTokenService.saveConfirmationToken(confirmationToken);

    // TODO: Send email

    return token;
  }

  public void enableAppUser(String email) {
    AppUser appUser =
        appUserRepository
            .findByEmail(email)
            .orElseThrow(() -> new IllegalStateException("email don't exists"));
    appUser.setEnabled(true);
    appUserRepository.save(appUser);
  }
}
