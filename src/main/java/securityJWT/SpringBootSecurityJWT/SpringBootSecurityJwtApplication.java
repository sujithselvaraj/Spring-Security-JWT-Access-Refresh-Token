package securityJWT.SpringBootSecurityJWT;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import securityJWT.SpringBootSecurityJWT.domain.Role;
import securityJWT.SpringBootSecurityJWT.domain.User;
import securityJWT.SpringBootSecurityJWT.service.UserService;

import java.util.ArrayList;

@SpringBootApplication
public class SpringBootSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootSecurityJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService)
	{
		return args->{
			userService.saveRole(new Role(null,"ROLE_USER"));
			userService.saveRole(new Role(null,"ROLE_MANAGER"));
			userService.saveRole(new Role(null,"ROLE_ADMIN"));
			userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null,"Sujith","sujithh","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"Nisanth","nisanthh","5678",new ArrayList<>()));
			userService.saveUser(new User(null,"Jothi","jothii","3456",new ArrayList<>()));
			userService.saveUser(new User(null,"Selvaraj","selvarajj","3456",new ArrayList<>()));

			userService.addRoleToUser("sujithh","ROLE_USER");
			userService.addRoleToUser("sujithh","ROLE_MANAGER");
			userService.addRoleToUser("nisanthh","ROLE_MANAGER");
			userService.addRoleToUser("jothii","ROLE_ADMIN");
			userService.addRoleToUser("selvarajj","ROLE_USER");
			userService.addRoleToUser("selvarajj","ROLE_ADMIN");
			userService.addRoleToUser("selvarajj","ROLE_SUPER_ADMIN");

		};
	}

}
